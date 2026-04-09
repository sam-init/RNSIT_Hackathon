"""
structure_agent.py — Repo Architecture Review Agent (Gemini-powered)
=====================================================================

A standalone AI agent that analyses a PR's repository structure and suggests
architectural improvements by posting inline GitHub PR comments.

How it fits into your existing system:
  - ai_agent.py  → reviews CODE quality (bugs, security, style)
  - structure_agent.py → reviews STRUCTURE (file names, folder layout, architecture)

Both agents run independently and post comments to the same PR.

Core flow:
  1. Receive PR webhook (repo + PR number)
  2. Fetch the full file tree of the repo via GitHub Trees API
  3. Detect the project type (Python/FastAPI, Node/Express, etc.)
  4. Ask Gemini to analyse the tree and produce structured recommendations
  5. Map each recommendation to a file path so GitHub can anchor it inline
  6. Post inline comments via the GitHub PR Review API

Environment variables required:
    GEMINI_API_KEY      — Google AI Studio key (https://aistudio.google.com/app/apikey)
    GITHUB_TOKEN        — Fine-grained PAT with pull_requests:write + contents:read
    WEBHOOK_SECRET      — Matches the secret in GitHub → Settings → Webhooks

Run standalone (for testing):
    python structure_agent.py --repo owner/repo --pr 42

Integrated into main.py webhook:
    from structure_agent import StructureAgent
    agent = StructureAgent()
    agent.review_pr(ctx.repo, ctx.pr_number, ctx.head_sha)
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import httpx

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("ph.structure")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

GEMINI_API_KEY: str = os.environ("GEMINI_API_KEY")
GITHUB_TOKEN: str = os.environ("GITHUB_TOKEN")
GITHUB_API_BASE: str = os.getenv("GITHUB_API_BASE", "https://api.github.com")

# Gemini model — gemini-1.5-flash is fast and cheap; swap to gemini-1.5-pro for deeper analysis
GEMINI_MODEL: str = os.getenv("STRUCTURE_GEMINI_MODEL", "gemini-1.5-flash")
GEMINI_API_BASE: str = "https://generativelanguage.googleapis.com/v1beta"

# Max files to include in the tree sent to Gemini (avoids token blowout on huge monorepos)
MAX_TREE_FILES: int = int(os.getenv("STRUCTURE_MAX_TREE_FILES", "300"))

# Max inline comments to post per PR (keep it low — don't spam the PR)
MAX_COMMENTS: int = int(os.getenv("STRUCTURE_MAX_COMMENTS", "15"))

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class StructureIssue:
    """
    A single structural finding produced by the Gemini agent.

    path:        The file or directory path the comment anchors to.
                 For file-level issues this is an exact path (e.g. "app/models.py").
                 For directory issues use the closest file in that dir.
    issue:       Short one-sentence description of the problem.
    suggestion:  The recommended fix (rename, move, create, delete).
    severity:    "high" | "medium" | "low"
    category:    "naming" | "placement" | "missing" | "redundant" | "organisation"
    line:        Always 1 for structure comments (file-level, not line-level).
    """
    path: str
    issue: str
    suggestion: str
    severity: str = "medium"
    category: str = "organisation"
    line: int = 1

    def to_github_payload(self) -> Dict[str, Any]:
        """Serialise to GitHub PR Review comment shape."""
        severity_emoji = {
            "high":   "🔴",
            "medium": "🟡",
            "low":    "🔵",
        }.get(self.severity, "⚠️")

        category_label = {
            "naming":       "📝 Naming",
            "placement":    "📁 File Placement",
            "missing":      "❓ Missing File",
            "redundant":    "♻️  Redundant",
            "organisation": "🏗️  Organisation",
        }.get(self.category, "🏗️  Structure")

        body = (
            f"{severity_emoji} **[STRUCTURE] {category_label}**\n\n"
            f"**Issue:** {self.issue}\n\n"
            f"**Recommended fix:** {self.suggestion}\n\n"
            f"_— ph Structure Agent (Gemini)_"
        )
        return {
            "path": self.path,
            "line": self.line,
            "side": "RIGHT",
            "body": body,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path": self.path,
            "line": self.line,
            "severity": self.severity,
            "category": self.category,
            "issue": self.issue,
            "suggestion": self.suggestion,
        }


@dataclass
class RepoTree:
    """
    Lightweight representation of a repository's file tree.
    Fetched via GitHub Trees API (recursive=1).
    """
    files: List[str] = field(default_factory=list)          # all file paths
    dirs: List[str] = field(default_factory=list)           # unique directory paths
    truncated: bool = False                                  # True if GitHub truncated the tree

    @property
    def tree_text(self) -> str:
        """Render the tree as indented text for the Gemini prompt."""
        lines = []
        for path in sorted(self.files):
            depth = path.count("/")
            indent = "  " * depth
            name = path.split("/")[-1]
            lines.append(f"{indent}{name}  ({path})")
        return "\n".join(lines)

    @property
    def flat_list(self) -> str:
        """Flat sorted list — used when tree_text is too long."""
        return "\n".join(sorted(self.files))


# ─────────────────────────────────────────────────────────────────────────────
# Project Type Detector
# ─────────────────────────────────────────────────────────────────────────────

class ProjectDetector:
    """
    Heuristic-based project type detector.
    Runs before the Gemini call so we can give it the right architecture template.
    """

    # Each entry: (label, required_files_or_dirs, optional_bonus_files)
    SIGNATURES: List[Tuple[str, List[str], List[str]]] = [
        ("Python / FastAPI",
            ["main.py", "requirements.txt"],
            ["routers/", "models/", "schemas/", "services/", "tests/", ".env"]),

        ("Python / Django",
            ["manage.py", "requirements.txt"],
            ["settings.py", "urls.py", "models.py", "views.py", "migrations/"]),

        ("Python / Flask",
            ["app.py", "requirements.txt"],
            ["templates/", "static/", "blueprints/"]),

        ("Node.js / Express",
            ["package.json", "index.js"],
            ["routes/", "controllers/", "middleware/", "models/", "tests/"]),

        ("Node.js / Next.js",
            ["package.json", "next.config.js"],
            ["pages/", "components/", "styles/", "public/", "lib/"]),

        ("React SPA",
            ["package.json", "src/App.js"],
            ["src/components/", "src/hooks/", "src/pages/", "public/"]),

        ("Python / Generic",
            ["requirements.txt"],
            ["src/", "tests/", "README.md", "setup.py", "pyproject.toml"]),

        ("Node.js / Generic",
            ["package.json"],
            ["src/", "tests/", "README.md"]),
    ]

    @classmethod
    def detect(cls, tree: RepoTree) -> Tuple[str, str]:
        """
        Returns (project_type, recommended_architecture_description).
        Falls back to "Unknown" if no signature matches.
        """
        file_set = set(tree.files)
        all_paths = " ".join(tree.files)

        for label, required, _ in cls.SIGNATURES:
            if all(
                any(req in path for path in file_set) or req in all_paths
                for req in required
            ):
                arch = cls._get_arch(label)
                logger.info("Detected project type: %s", label)
                return label, arch

        return "Unknown", cls._get_arch("Unknown")

    @staticmethod
    def _get_arch(project_type: str) -> str:
        """Return the recommended architecture description for this project type."""
        architectures = {
            "Python / FastAPI": """
Recommended FastAPI project structure:
├── main.py                  # FastAPI app entry point
├── requirements.txt         # or pyproject.toml
├── .env                     # secrets (never commit)
├── .env.example             # committed template
├── README.md
├── routers/                 # one file per resource (users.py, items.py)
├── models/                  # SQLAlchemy / Pydantic models
├── schemas/                 # Pydantic request/response schemas
├── services/                # business logic (no HTTP concerns here)
├── dependencies/            # FastAPI Depends() helpers (auth.py, db.py)
├── core/                    # config.py, security.py, logging.py
└── tests/
    ├── conftest.py
    └── test_*.py            # mirrors routers/ structure
""",
            "Python / Django": """
Recommended Django project structure:
├── manage.py
├── requirements.txt
├── README.md
├── config/                  # settings/, urls.py, wsgi.py, asgi.py
│   ├── settings/
│   │   ├── base.py
│   │   ├── development.py
│   │   └── production.py
├── apps/                    # each Django app in its own directory
│   └── myapp/
│       ├── models.py
│       ├── views.py
│       ├── urls.py
│       ├── serializers.py
│       ├── admin.py
│       └── tests/
└── static/ / templates/
""",
            "Node.js / Express": """
Recommended Express project structure:
├── index.js / server.js     # app entry point
├── package.json
├── .env / .env.example
├── README.md
├── src/
│   ├── routes/              # one file per resource
│   ├── controllers/         # request handlers (thin layer)
│   ├── services/            # business logic
│   ├── models/              # DB models (Mongoose, Sequelize, Prisma)
│   ├── middleware/          # auth.js, errorHandler.js, rateLimit.js
│   └── config/              # database.js, logger.js
└── tests/
    └── *.test.js
""",
            "Node.js / Next.js": """
Recommended Next.js project structure:
├── package.json
├── next.config.js
├── README.md
├── public/                  # static assets
├── src/
│   ├── app/                 # App Router (Next.js 13+)
│   ├── components/          # reusable UI components
│   ├── lib/                 # utilities, helpers
│   ├── hooks/               # custom React hooks
│   └── styles/              # global CSS / Tailwind config
└── tests/
""",
            "React SPA": """
Recommended React project structure:
├── package.json
├── public/
└── src/
    ├── App.js / App.tsx
    ├── index.js
    ├── components/          # reusable components (PascalCase.jsx)
    ├── pages/               # route-level components
    ├── hooks/               # custom hooks (use*.js)
    ├── context/             # React Context providers
    ├── services/            # API call functions
    ├── utils/               # pure helper functions
    └── styles/
""",
            "Unknown": """
General best practices for any project:
- Use a clear src/ or app/ directory for source code
- Keep tests/ or __tests__/ separate from source
- Have a README.md at the root
- Use .env.example to document required environment variables (never commit .env)
- Separate concerns: models, services, API routes should be in different files/dirs
- Use consistent naming: snake_case for Python, camelCase or kebab-case for JS
- Keep the root clean — configuration files at root, source in subdirectories
""",
        }
        # Match prefix
        for key, arch in architectures.items():
            if project_type.startswith(key.split("/")[0].strip()):
                if key in project_type or project_type == "Unknown":
                    return architectures.get(project_type, architectures["Unknown"])
        return architectures.get(project_type, architectures["Unknown"])


# ─────────────────────────────────────────────────────────────────────────────
# Gemini Client
# ─────────────────────────────────────────────────────────────────────────────

class GeminiClient:
    """
    Minimal Gemini REST API client.
    Uses the generateContent endpoint directly (no SDK dependency).

    Endpoint: POST /v1beta/models/{model}:generateContent?key={api_key}
    """

    def __init__(
        self,
        api_key: str = GEMINI_API_KEY,
        model: str = GEMINI_MODEL,
        max_retries: int = 3,
        timeout: float = 60.0,
    ) -> None:
        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is not set. "
                "Get one at https://aistudio.google.com/app/apikey"
            )
        self.api_key = api_key
        self.model = model
        self.max_retries = max_retries
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def generate(self, prompt: str, temperature: float = 0.1) -> str:
        """
        Send a prompt to Gemini and return the text response.
        temperature=0.1 keeps output deterministic and precise (less creative hallucination).
        """
        url = f"{GEMINI_API_BASE}/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": 4096,
                "responseMimeType": "application/json",   # ask Gemini to return JSON directly
            },
            "systemInstruction": {
                "parts": [{
                    "text": (
                        "You are a senior software architect specialising in project structure "
                        "and code organisation. You review repository file trees and produce "
                        "precise, actionable structural recommendations. "
                        "You always return ONLY valid JSON — no preamble, no markdown fences, "
                        "no explanations outside the JSON structure."
                    )
                }]
            },
        }

        last_exc: Optional[Exception] = None
        for attempt in range(1, self.max_retries + 1):
            try:
                resp = self._client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()

                # Extract text from Gemini's nested response structure
                candidates = data.get("candidates", [])
                if not candidates:
                    raise ValueError("Gemini returned no candidates")

                content = candidates[0].get("content", {})
                parts = content.get("parts", [])
                if not parts:
                    raise ValueError("Gemini returned empty parts")

                return parts[0].get("text", "")

            except httpx.HTTPStatusError as exc:
                last_exc = exc
                logger.warning(
                    "Gemini HTTP error (attempt %d/%d): %d — %s",
                    attempt, self.max_retries,
                    exc.response.status_code, exc.response.text[:200],
                )
                if 400 <= exc.response.status_code < 500 and exc.response.status_code != 429:
                    break   # Don't retry on bad requests (wrong key, bad payload)

            except Exception as exc:
                last_exc = exc
                logger.warning("Gemini call failed (attempt %d/%d): %s", attempt, self.max_retries, exc)

            if attempt < self.max_retries:
                sleep_for = 2 ** (attempt - 1)
                logger.info("Retrying Gemini in %ds…", sleep_for)
                time.sleep(sleep_for)

        raise RuntimeError(f"Gemini unavailable after {self.max_retries} attempts: {last_exc}")

    def close(self) -> None:
        self._client.close()


# ─────────────────────────────────────────────────────────────────────────────
# GitHub Client (repo tree + PR comments)
# ─────────────────────────────────────────────────────────────────────────────

class StructureGitHubClient:
    """
    GitHub API calls needed by the structure agent:
      - get_repo_tree()   → full recursive file tree via Trees API
      - get_pr_files()    → list of files changed in the PR
      - post_pr_review()  → post inline comments via PR Review API
      - post_comment()    → post a PR-level summary comment
    """

    def __init__(self, token: str = GITHUB_TOKEN, base_url: str = GITHUB_API_BASE) -> None:
        if not token:
            raise RuntimeError("GITHUB_TOKEN is not set.")
        self._base = base_url.rstrip("/")
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "ph-structure-agent/1.0",
            },
            timeout=30.0,
            follow_redirects=True,
        )

    def get_repo_tree(self, repo: str, sha: str) -> RepoTree:
        """
        Fetch the complete recursive file tree for a commit SHA.
        Uses GET /repos/{owner}/{repo}/git/trees/{sha}?recursive=1

        GitHub truncates trees > 100,000 entries (very unlikely in practice).
        We further limit to MAX_TREE_FILES to keep the Gemini prompt manageable.
        """
        url = f"{self._base}/repos/{repo}/git/trees/{sha}?recursive=1"
        resp = self._client.get(url)
        resp.raise_for_status()
        data = resp.json()

        tree_items = data.get("tree", [])
        truncated = data.get("truncated", False)

        files = [
            item["path"]
            for item in tree_items
            if item.get("type") == "blob"   # "blob" = file, "tree" = directory
        ]

        dirs = list({
            "/".join(f.split("/")[:-1])
            for f in files
            if "/" in f
        })

        # Limit to MAX_TREE_FILES — keep the most "interesting" paths
        # (shorter paths first = root-level config files, then deeper source)
        files = sorted(files, key=lambda p: (p.count("/"), p))[:MAX_TREE_FILES]

        logger.info(
            "Repo tree: %d files fetched (truncated=%s) for %s@%s",
            len(files), truncated, repo, sha[:8],
        )
        return RepoTree(files=files, dirs=dirs, truncated=truncated)

    def get_pr_files(self, repo: str, pr_number: int) -> List[str]:
        """
        Get the list of files changed in this PR.
        Used to anchor comments to files that actually exist in the PR diff.
        """
        url = f"{self._base}/repos/{repo}/pulls/{pr_number}/files"
        resp = self._client.get(url)
        resp.raise_for_status()
        return [f["filename"] for f in resp.json()]

    def post_pr_review(
        self,
        repo: str,
        pr_number: int,
        commit_id: str,
        comments: List[StructureIssue],
        body: str = "",
    ) -> Dict[str, Any]:
        """
        Post a PR Review with inline comments via:
        POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews
        """
        url = f"{self._base}/repos/{repo}/pulls/{pr_number}/reviews"
        github_comments = [c.to_github_payload() for c in comments]

        payload: Dict[str, Any] = {
            "commit_id": commit_id,
            "body": body,
            "event": "COMMENT",
            "comments": github_comments,
        }

        resp = self._client.post(url, json=payload)
        if resp.status_code not in (200, 201):
            logger.error(
                "GitHub Review API error: HTTP %d — %s",
                resp.status_code, resp.text[:500],
            )
        resp.raise_for_status()

        review_id = resp.json().get("id")
        logger.info(
            "Structure review posted: repo=%s pr=%d review_id=%s comments=%d",
            repo, pr_number, review_id, len(comments),
        )
        return resp.json()

    def post_comment(self, repo: str, issue_number: int, body: str) -> Dict[str, Any]:
        """Post a PR-level (non-inline) comment."""
        url = f"{self._base}/repos/{repo}/issues/{issue_number}/comments"
        resp = self._client.post(url, json={"body": body})
        resp.raise_for_status()
        return resp.json()

    def close(self) -> None:
        self._client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Gemini Prompt Builder
# ─────────────────────────────────────────────────────────────────────────────

class PromptBuilder:
    """Builds the structured Gemini prompt for repo structure analysis."""

    SCHEMA = """
[
  {
    "path": "<exact file path from the tree, e.g. 'src/utils.py'>",
    "issue": "<one sentence describing the structural problem>",
    "suggestion": "<concrete action: rename to X, move to Y/, create Z, delete W>",
    "severity": "high | medium | low",
    "category": "naming | placement | missing | redundant | organisation"
  }
]
"""

    @classmethod
    def build(
        cls,
        tree: RepoTree,
        project_type: str,
        recommended_arch: str,
        pr_files: List[str],
    ) -> str:
        pr_files_block = "\n".join(f"  - {f}" for f in pr_files[:50])
        tree_block = tree.flat_list  # flat list is more token-efficient than indented tree

        return f"""You are reviewing the repository structure of a {project_type} project.

## Files changed in this PR (anchor your comments to these where possible):
{pr_files_block}

## Full repository file tree (up to {MAX_TREE_FILES} files):
{tree_block}

## Recommended architecture for this project type:
{recommended_arch}

## Your task:
Compare the actual file tree against the recommended architecture.
Identify structural issues such as:
- Files with wrong names (e.g. "helper.py" instead of "utils.py", "DBModels.py" instead of "models.py")
- Files in wrong directories (e.g. business logic in routers/, models in the root)
- Missing critical files (.env.example, README.md, tests/, __init__.py where needed)
- Redundant or duplicated files
- Inconsistent naming conventions (mixing snake_case and camelCase in Python, etc.)
- Flat structure that should be modularised
- Config/secrets that appear to be committed (.env, *.pem, *.key)

## Rules:
- Only report REAL structural issues — do not flag things that are acceptable
- Prefer to anchor comments to files that appear in the "PR files" list above
- If the issue is about a missing file, anchor to the closest existing file in that directory
- If no related PR file exists, anchor to the root-level file most relevant (e.g. README.md, main.py)
- Limit to the most impactful {MAX_COMMENTS} issues maximum
- Do NOT comment on code content — only on file/directory structure
- Return ONLY a valid JSON array matching this exact schema (no markdown, no explanation):

{cls.SCHEMA}

If there are no structural issues, return an empty array: []
"""


# ─────────────────────────────────────────────────────────────────────────────
# Structure Agent — Main Orchestrator
# ─────────────────────────────────────────────────────────────────────────────

class StructureAgent:
    """
    The main structure review agent.

    Orchestrates: GitHub tree fetch → project detection → Gemini analysis
    → comment mapping → GitHub PR review post.

    Usage from main.py webhook:
        agent = StructureAgent()
        agent.review_pr(ctx.repo, ctx.pr_number, ctx.head_sha)
        agent.close()

    Or use as a context manager:
        with StructureAgent() as agent:
            agent.review_pr(ctx.repo, ctx.pr_number, ctx.head_sha)
    """

    def __init__(self) -> None:
        self.gemini = GeminiClient()
        self.github = StructureGitHubClient()

    def review_pr(self, repo: str, pr_number: int, head_sha: str) -> List[StructureIssue]:
        """
        Full pipeline: fetch tree → analyse → post comments.
        Returns the list of issues found (useful for testing).
        """
        logger.info("▶ Structure review: %s#%d @ %s", repo, pr_number, head_sha[:8])

        # Step 1: Post acknowledgement
        self.github.post_comment(
            repo, pr_number,
            "## 🏗️ ph Structure Agent\n\n"
            "Analysing repository architecture… inline suggestions will appear shortly.",
        )

        # Step 2: Fetch repo tree and PR file list
        tree = self.github.get_repo_tree(repo, head_sha)
        pr_files = self.github.get_pr_files(repo, pr_number)
        logger.info("PR touches %d files", len(pr_files))

        # Step 3: Detect project type
        project_type, recommended_arch = ProjectDetector.detect(tree)

        # Step 4: Build prompt and call Gemini
        prompt = PromptBuilder.build(tree, project_type, recommended_arch, pr_files)
        logger.info("Sending tree to Gemini (%s)…", self.gemini.model)

        raw_response = self.gemini.generate(prompt)
        logger.debug("Gemini raw response: %r", raw_response[:500])

        # Step 5: Parse Gemini's JSON response
        issues = self._parse_issues(raw_response, tree)
        logger.info("Gemini returned %d structural issues", len(issues))

        if not issues:
            self.github.post_pr_review(
                repo=repo,
                pr_number=pr_number,
                commit_id=head_sha,
                comments=[],
                body=(
                    "## 🏗️ ph Structure Agent\n\n"
                    f"✅ **No structural issues found** for this `{project_type}` project.\n\n"
                    "Repository architecture looks clean! 🎉"
                ),
            )
            return []

        # Step 6: Filter to only files that exist in the tree
        # (Gemini might hallucinate paths — anchor to real files)
        valid_issues = self._validate_paths(issues, tree, pr_files)
        logger.info("%d issues after path validation", len(valid_issues))

        # Step 7: Cap at MAX_COMMENTS, prioritise by severity
        severity_order = {"high": 0, "medium": 1, "low": 2}
        top_issues = sorted(valid_issues, key=lambda i: severity_order.get(i.severity, 3))
        top_issues = top_issues[:MAX_COMMENTS]

        # Step 8: Post inline comments via GitHub PR Review API
        review_body = self._build_summary(project_type, top_issues, tree.truncated)
        self.github.post_pr_review(
            repo=repo,
            pr_number=pr_number,
            commit_id=head_sha,
            comments=top_issues,
            body=review_body,
        )

        logger.info("✅ Structure review complete: %d comments posted", len(top_issues))
        return top_issues

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _parse_issues(self, raw_response: str, tree: RepoTree) -> List[StructureIssue]:
        """
        Parse Gemini's JSON response into StructureIssue objects.
        Handles stray markdown fences and non-array responses gracefully.
        """
        clean = raw_response.strip()
        # Strip any accidental markdown code fences
        if clean.startswith("```"):
            clean = clean.lstrip("`").lstrip("json").strip()
        if clean.endswith("```"):
            clean = clean.rstrip("`").strip()

        try:
            data = json.loads(clean)
        except json.JSONDecodeError as exc:
            logger.warning("Gemini returned non-JSON: %s | raw=%r", exc, raw_response[:300])
            return []

        if not isinstance(data, list):
            logger.warning("Gemini returned non-array JSON: %s", type(data))
            return []

        issues = []
        for item in data:
            try:
                issues.append(StructureIssue(
                    path=str(item.get("path", "README.md")),
                    issue=str(item.get("issue", "")),
                    suggestion=str(item.get("suggestion", "")),
                    severity=str(item.get("severity", "medium")).lower(),
                    category=str(item.get("category", "organisation")).lower(),
                    line=1,  # structure issues always anchor to line 1
                ))
            except Exception as exc:
                logger.warning("Skipping malformed issue item: %s | item=%s", exc, item)

        return issues

    def _validate_paths(
        self,
        issues: List[StructureIssue],
        tree: RepoTree,
        pr_files: List[str],
    ) -> List[StructureIssue]:
        """
        Ensure each issue's path exists in the repo tree.
        If Gemini hallucinated a path, try to find the closest real file.
        Priority: PR files > root files > any tree file.
        """
        file_set = set(tree.files)
        pr_file_set = set(pr_files)
        validated = []

        for issue in issues:
            if issue.path in file_set:
                # Perfect — path exists
                validated.append(issue)
                continue

            # Try to find the closest PR file in the same directory
            issue_dir = "/".join(issue.path.split("/")[:-1])
            same_dir_pr = [f for f in pr_files if f.startswith(issue_dir + "/")]
            if same_dir_pr:
                issue.path = same_dir_pr[0]
                validated.append(issue)
                continue

            # Fall back to any PR file in the same directory
            same_dir_tree = [f for f in tree.files if f.startswith(issue_dir + "/")]
            if same_dir_tree:
                issue.path = same_dir_tree[0]
                validated.append(issue)
                continue

            # Last resort: anchor to a root-level file
            root_candidates = ["README.md", "main.py", "index.js", "package.json",
                                "requirements.txt", "setup.py", "pyproject.toml"]
            for candidate in root_candidates:
                if candidate in file_set:
                    issue.path = candidate
                    validated.append(issue)
                    break
            else:
                # If we still can't find a valid path, skip the issue
                logger.debug("Dropping issue with unresolvable path: %s", issue.path)

        return validated

    @staticmethod
    def _build_summary(
        project_type: str,
        issues: List[StructureIssue],
        was_truncated: bool,
    ) -> str:
        """Build the top-level Markdown review summary."""
        high = sum(1 for i in issues if i.severity == "high")
        medium = sum(1 for i in issues if i.severity == "medium")
        low = sum(1 for i in issues if i.severity == "low")

        lines = [
            "## 🏗️ ph Structure Agent — Architecture Review",
            "",
            f"**Project type detected:** `{project_type}`",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 High   | {high} |",
            f"| 🟡 Medium | {medium} |",
            f"| 🔵 Low    | {low} |",
            f"| **Total** | **{len(issues)}** |",
            "",
        ]
        if was_truncated:
            lines.append(
                "> ⚠️ **Note:** Repository tree was truncated — "
                "only the first portion was analysed."
            )
        lines += [
            "",
            "_Inline suggestions are anchored to the relevant files below._",
            "",
            "---",
            "_Powered by ph Structure Agent (Gemini)_",
        ]
        return "\n".join(lines)

    def close(self) -> None:
        self.gemini.close()
        self.github.close()

    def __enter__(self) -> "StructureAgent":
        return self

    def __exit__(self, *args: Any) -> None:
        self.close()


# ─────────────────────────────────────────────────────────────────────────────
# CLI — for standalone testing
# ─────────────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="structure_agent",
        description="AI-powered repo structure reviewer (Gemini)",
    )
    parser.add_argument("--repo", required=True, metavar="OWNER/REPO",
                        help="GitHub repo (e.g. acme/myapp)")
    parser.add_argument("--pr", required=True, type=int, metavar="NUMBER",
                        help="Pull request number")
    parser.add_argument("--sha", metavar="SHA",
                        help="HEAD commit SHA (fetched from PR if omitted)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print issues as JSON instead of posting to GitHub")
    return parser


def _get_pr_head_sha(github: StructureGitHubClient, repo: str, pr_number: int) -> str:
    """Fetch the HEAD SHA of a PR (used when --sha is not provided)."""
    url = f"{GITHUB_API_BASE}/repos/{repo}/pulls/{pr_number}"
    resp = github._client.get(url)
    resp.raise_for_status()
    return resp.json()["head"]["sha"]


def main() -> int:
    parser = build_cli()
    args = parser.parse_args()

    with StructureAgent() as agent:
        sha = args.sha
        if not sha:
            sha = _get_pr_head_sha(agent.github, args.repo, args.pr)
            logger.info("Resolved HEAD SHA: %s", sha[:8])

        if args.dry_run:
            # Analyse but print JSON instead of posting to GitHub
            tree = agent.github.get_repo_tree(args.repo, sha)
            pr_files = agent.github.get_pr_files(args.repo, args.pr)
            project_type, recommended_arch = ProjectDetector.detect(tree)
            prompt = PromptBuilder.build(tree, project_type, recommended_arch, pr_files)
            raw = agent.gemini.generate(prompt)
            issues = agent._parse_issues(raw, tree)
            validated = agent._validate_paths(issues, tree, pr_files)
            print(json.dumps([i.to_dict() for i in validated], indent=2))
        else:
            agent.review_pr(args.repo, args.pr, sha)

    return 0


if __name__ == "__main__":
    sys.exit(main())