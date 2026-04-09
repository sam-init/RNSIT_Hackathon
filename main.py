"""
main.py — GitHub Webhook Receiver with Inline Review Comment Support
=====================================================================

Receives GitHub PR webhook events, verifies HMAC-SHA256 signatures,
runs the ph AI review engine, and posts INLINE COMMENTS via the GitHub
Pull Request Review API — not just PR-level comments.

Environment variables:
    GITHUB_TOKEN    — Fine-grained PAT: pull_requests:write + contents:read
    WEBHOOK_SECRET  — Matches the secret in GitHub → Settings → Webhooks

Run locally:
    uvicorn main:app --reload --port 8000

Production (Render, Railway, Fly.io):
    uvicorn main:app --host 0.0.0.0 --port $PORT --workers 2
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

# Import the review engine from ai_agent.py (same package)
from ai_agent import (
    DiffParser,
    InlineComment,
    MegaLLM,
    SecurityScanner,
)

# Import the structure review agent
from structure_agent import StructureAgent

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("ph.webhook")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

def _require_env(name: str) -> str:
    """
    Read an env var and crash loudly at startup if it's missing.

    Original bug: os.getenv("/etc/secrets/GITHUB_TOKEN") passes a FILE PATH
    as the variable name — always returns None. Correct: os.environ.get("GITHUB_TOKEN").
    """
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(
            f"Required environment variable '{name}' is not set. "
            "Set it in your deployment secrets (Render/Railway/Fly secret env)."
        )
    return value


GITHUB_TOKEN: str = _require_env("GITHUB_TOKEN")
WEBHOOK_SECRET: bytes = _require_env("WEBHOOK_SECRET").encode("utf-8")

# Externalise API base so tests can point at a mock (e.g. responses library)
GITHUB_API_BASE: str = os.getenv("GITHUB_API_BASE", "https://api.github.com")

# Concurrency: one thread per PR review job.
# Switch to Celery/ARQ for production-scale workloads with retry persistence.
MAX_WORKERS: int = int(os.getenv("PH_WEBHOOK_WORKERS", "4"))

# Review behaviour flags
ENABLE_INLINE_COMMENTS: bool = os.getenv("PH_INLINE_COMMENTS", "true").lower() == "true"
ENABLE_SECURITY_SCAN: bool = os.getenv("PH_SECURITY_SCAN", "true").lower() == "true"
# Maximum diff size to send to LLM (avoids blowing token budgets)
MAX_DIFF_BYTES: int = int(os.getenv("PH_MAX_DIFF_BYTES", str(200_000)))  # 200 KB default

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class PRContext:
    """
    Immutable value object for the essential fields of a PR webhook event.
    Parsing this once at the top of the handler keeps process_pr() clean.

    commits_url: used to fetch commit SHAs (needed for review commit_id)
    diff_url:    the raw unified diff for this PR
    head_sha:    the HEAD commit SHA — required by the GitHub Review API
    """
    repo: str           # "owner/repo"
    pr_number: int
    pr_title: str
    pr_url: str
    author: str
    base_branch: str
    head_branch: str
    head_sha: str       # HEAD commit SHA — required by GitHub Review API
    diff_url: str
    commits_url: str

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "PRContext":
        """
        Extract a PRContext from a raw GitHub webhook payload.
        Raises ValueError (not KeyError) so callers can produce a 422 response.
        """
        try:
            pr = payload["pull_request"]
            return cls(
                repo=payload["repository"]["full_name"],
                pr_number=pr["number"],
                pr_title=pr["title"],
                pr_url=pr["html_url"],
                author=pr["user"]["login"],
                base_branch=pr["base"]["ref"],
                head_branch=pr["head"]["ref"],
                head_sha=pr["head"]["sha"],   # ← needed for review API
                diff_url=pr["diff_url"],
                commits_url=pr["commits_url"],
            )
        except KeyError as exc:
            raise ValueError(f"Malformed PR payload — missing key: {exc}") from exc


# ─────────────────────────────────────────────────────────────────────────────
# Security — HMAC Verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_github_signature(payload_body: bytes, signature_header: Optional[str]) -> None:
    """
    Verify the X-Hub-Signature-256 header using constant-time HMAC comparison.

    Security notes:
    - Raw body bytes are verified BEFORE JSON parsing — ensures we sign exactly
      what GitHub signed, not a re-serialised version.
    - hmac.compare_digest() prevents timing side-channel attacks.
    - Header is lowercased before comparison to handle case normalisation.

    Raises HTTPException(403) on any verification failure.
    """
    if not signature_header:
        logger.warning("Rejected: missing X-Hub-Signature-256")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Missing signature header")

    # Format: "sha256=<hex>"
    parts = signature_header.split("=", maxsplit=1)
    if len(parts) != 2 or parts[0] != "sha256":
        logger.warning("Rejected: malformed signature header")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Malformed signature header")

    expected = hmac.HMAC(WEBHOOK_SECRET, payload_body, hashlib.sha256).hexdigest()

    # Both operands must be the same type (str) for compare_digest
    if not hmac.compare_digest(expected, parts[1].lower()):
        logger.warning("Rejected: signature mismatch")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Signature mismatch")

    logger.debug("Signature verified ✓")


# ─────────────────────────────────────────────────────────────────────────────
# GitHub API Client
# ─────────────────────────────────────────────────────────────────────────────

class GitHubClient:
    """
    Thin wrapper around the GitHub REST API v3.

    Uses httpx.Client (synchronous) because all calls happen inside
    ThreadPoolExecutor worker threads — not in the async event loop.

    Connection pooling: a single httpx.Client reuses TCP connections across
    requests, avoiding the overhead of a new TLS handshake per call.

    Key methods:
      - post_pr_review()  → creates a GitHub Pull Request Review with inline comments
      - post_comment()    → posts a PR-level (non-inline) issue comment
      - get_diff()        → fetches the raw unified diff for a PR
    """

    def __init__(self, token: str, base_url: str = GITHUB_API_BASE) -> None:
        self._base = base_url.rstrip("/")
        # Build a session with all auth headers set once — reused for every request
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",  # pin to stable API version
                "User-Agent": "ph-webhook/2.0",
            },
            timeout=20.0,   # fail fast — don't block worker threads
            follow_redirects=True,
        )

    def post_pr_review(
        self,
        repo: str,
        pr_number: int,
        commit_id: str,
        comments: List[InlineComment],
        body: str = "",
        event: str = "COMMENT",
    ) -> Dict[str, Any]:
        """
        Submit a Pull Request Review containing inline comments.

        This uses the GitHub Pull Request Reviews API:
        POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews

        A Review groups multiple inline comments into a single atomic review submission.
        This is preferred over posting individual comments because:
          - It shows as a single review in the PR timeline (less noise)
          - All comments are associated with the same commit SHA
          - Reviewers can approve/request-changes via event parameter

        Args:
            repo:       "owner/repo"
            pr_number:  Pull request number
            commit_id:  HEAD commit SHA of the PR (from PRContext.head_sha)
            comments:   List of InlineComment objects to post as inline review comments
            body:       Optional review summary shown at the top of the review
            event:      "COMMENT" | "APPROVE" | "REQUEST_CHANGES"

        Returns:
            The created review object from the GitHub API.

        Raises:
            httpx.HTTPStatusError on API errors.
        """
        url = f"{self._base}/repos/{repo}/pulls/{pr_number}/reviews"

        # Convert InlineComment objects to GitHub's review comment payload shape
        github_comments = [c.to_github_payload() for c in comments]

        payload: Dict[str, Any] = {
            "commit_id": commit_id,
            "body": body,
            "event": event,
            "comments": github_comments,
        }

        response = self._client.post(url, json=payload)

        # Log the response for debugging — GitHub Review API errors can be subtle
        if response.status_code not in (200, 201):
            logger.error(
                "GitHub Review API error: HTTP %d — %s",
                response.status_code, response.text[:500]
            )
        response.raise_for_status()

        review_id = response.json().get("id")
        logger.info(
            "PR review posted: repo=%s pr=%d review_id=%s comments=%d",
            repo, pr_number, review_id, len(comments),
        )
        return response.json()

    def post_comment(self, repo: str, issue_number: int, body: str) -> Dict[str, Any]:
        """
        Post a PR-level comment (not inline — visible at the bottom of the PR).
        Used for summary comments (e.g., overall health score, security report).
        """
        url = f"{self._base}/repos/{repo}/issues/{issue_number}/comments"
        response = self._client.post(url, json={"body": body})
        response.raise_for_status()
        logger.info("Comment posted on %s#%d", repo, issue_number)
        return response.json()

    def get_diff(self, diff_url: str) -> str:
        """
        Fetch the raw unified diff for a PR.
        GitHub serves the diff with Accept: application/vnd.github.diff.
        """
        response = self._client.get(
            diff_url,
            headers={"Accept": "application/vnd.github.diff"},
        )
        response.raise_for_status()
        return response.text

    def get_readme(self, repo: str) -> Optional[str]:
        """
        Fetch the raw README content for *repo* via the GitHub Readme API.

        Uses GET /repos/{owner}/{repo}/readme instead of /contents/README.md
        because the /readme endpoint:
          - Auto-detects any README filename (README.md, readme.md, README.rst, …)
          - Is case-insensitive on all platforms
          - Returns the default-branch README without needing to specify a path

        Handles two response formats from GitHub:
          1. Raw text  → returned directly when Accept: vnd.github.raw is honoured
          2. JSON blob → base64-encoded content field decoded as UTF-8 fallback

        Returns None (treated as "README missing") on 404 or any error.
        """
        url = f"{self._base}/repos/{repo}/readme"
        try:
            response = self._client.get(
                url,
                headers={"Accept": "application/vnd.github.raw"},  # raw bytes, not JSON
            )
            if response.status_code == 404:
                return None  # repo has no README — not an error

            response.raise_for_status()

            # GitHub occasionally ignores the Accept header and returns JSON with
            # base64-encoded content (observed on some enterprise instances).
            # Detect this and decode manually.
            content_type = response.headers.get("content-type", "")
            text = response.text.strip()
            if "json" in content_type or text.startswith("{"):
                try:
                    import base64 as _base64
                    data = response.json()
                    raw_bytes = _base64.b64decode(data["content"])
                    return raw_bytes.decode("utf-8", errors="replace")
                except Exception:
                    pass  # fall through to returning raw text as-is

            return text

        except Exception as exc:
            logger.warning("README fetch failed for %s: %s", repo, exc)
            return None

    def close(self) -> None:
        """Release connection pool — call on server shutdown."""
        self._client.close()


# ─────────────────────────────────────────────────────────────────────────────
# PR Review Pipeline
# ─────────────────────────────────────────────────────────────────────────────

def process_pr(ctx: PRContext, github: GitHubClient, llm: MegaLLM) -> None:
    """
    Full AI review pipeline for a newly opened PR.

    Steps:
      1. Post acknowledgement comment (instant feedback to author)
      2. Fetch the raw diff from GitHub
      3. Run pattern-based security scanner (fast, no LLM needed)
      4. Run LLM-based inline review (per-file, structured JSON output)
      5. Post inline comments via GitHub PR Review API
      6. Post a summary comment with overall findings

    This runs in a ThreadPoolExecutor worker thread.  Any exception is caught
    and logged — we never let one PR crash the worker pool.

    Args:
        ctx:    Immutable PR context (repo, number, head SHA, diff URL, …)
        github: Shared GitHubClient with connection pooling
        llm:    MegaLLM instance (one per worker thread — not shared across threads
                because conversation_history is instance-level state)
    """
    logger.info("▶ Processing PR %s#%d: '%s'", ctx.repo, ctx.pr_number, ctx.pr_title)

    try:
        # ── Step 1: Acknowledge immediately ────────────────────────────────────
        ack = (
            f"## 🤖 ph AI Review\n\n"
            f"Review started for **{ctx.pr_title}** by @{ctx.author}.\n"
            f"> `{ctx.head_branch}` → `{ctx.base_branch}` | commit `{ctx.head_sha[:8]}`\n\n"
            f"⏳ Analysing diff — inline comments will appear shortly…"
        )
        github.post_comment(ctx.repo, ctx.pr_number, ack)

        # ── Step 2: Fetch diff ─────────────────────────────────────────────────
        logger.info("Fetching diff: %s", ctx.diff_url)
        diff_text = github.get_diff(ctx.diff_url)

        if not diff_text.strip():
            github.post_comment(ctx.repo, ctx.pr_number, "ℹ️ **ph**: Diff is empty — nothing to review.")
            return

        # Truncate very large diffs to avoid blowing LLM token limits.
        was_truncated = False
        if len(diff_text.encode("utf-8")) > MAX_DIFF_BYTES:
            diff_text = diff_text.encode("utf-8")[:MAX_DIFF_BYTES].decode("utf-8", errors="ignore")
            was_truncated = True
            logger.warning("Diff truncated to %d bytes for PR %s#%d", MAX_DIFF_BYTES, ctx.repo, ctx.pr_number)

        # ── Step 3: Parse diff ─────────────────────────────────────────────────
        parsed = DiffParser.parse(diff_text)
        logger.info(
            "Parsed diff: %d files, %d hunks", len(parsed.files), len(parsed.hunks)
        )

        # ── Step 4: Pattern-based security pre-scan ────────────────────────────
        security_comments: List[InlineComment] = []
        if ENABLE_SECURITY_SCAN:
            security_comments = SecurityScanner.scan_diff(parsed)
            logger.info("Pattern scan: %d security hits", len(security_comments))

        # ── Step 5: LLM inline review ──────────────────────────────────────────
        inline_comments: List[InlineComment] = []
        if ENABLE_INLINE_COMMENTS:
            inline_comments = llm.review_inline(
                parsed, existing_security_comments=security_comments
            )
            logger.info("AI review: %d inline comments total", len(inline_comments))
        else:
            inline_comments = security_comments

        # ── Step 5a: Code Quality Agent ────────────────────────────────────────
        try:
            quality_comments = llm.analyze_code_quality(parsed)
            logger.info("Code quality agent: %d findings", len(quality_comments))
        except Exception:
            quality_comments = []
            logger.warning("Code quality agent failed (non-fatal) for PR %s#%d", ctx.repo, ctx.pr_number)

        # ── Step 5b: Performance Agent ─────────────────────────────────────────
        try:
            perf_comments = llm.analyze_performance(parsed)
            logger.info("Performance agent: %d findings", len(perf_comments))
        except Exception:
            perf_comments = []
            logger.warning("Performance agent failed (non-fatal) for PR %s#%d", ctx.repo, ctx.pr_number)

        # ── Merge: existing + quality + performance (deduplicate on path+line+category)
        if quality_comments or perf_comments:
            existing_keys = {(c.path, c.line, c.category) for c in inline_comments}
            for c in quality_comments + perf_comments:
                if (c.path, c.line, c.category) not in existing_keys:
                    inline_comments.append(c)
                    existing_keys.add((c.path, c.line, c.category))
            logger.info(
                "Merged total: %d inline comments for PR %s#%d",
                len(inline_comments), ctx.repo, ctx.pr_number,
            )

        # ── Step 5c: README Consistency Agent ─────────────────────────────────
        try:
            readme_text = github.get_readme(ctx.repo)
            readme_comments = llm.analyze_readme_consistency(parsed, readme_text)
            logger.info("README consistency agent: %d findings", len(readme_comments))
            if readme_comments:
                existing_keys = {(c.path, c.line, c.category) for c in inline_comments}
                for c in readme_comments:
                    if (c.path, c.line, c.category) not in existing_keys:
                        inline_comments.append(c)
                        existing_keys.add((c.path, c.line, c.category))
        except Exception:
            logger.warning("README consistency agent failed (non-fatal) for PR %s#%d", ctx.repo, ctx.pr_number)

        # ── Step 5d: Safety Validation Layer ──────────────────────────────────
        # GitHub Review API returns HTTP 422 "Line could not be resolved" when ANY
        # comment references a file path or line number not present in the PR diff.
        # A single invalid comment causes the ENTIRE review batch to be rejected.
        # This block validates and fixes every comment BEFORE sending to GitHub.

        # Build a map: file_path → set of valid new-file line numbers from the diff
        valid_lines_per_file: Dict[str, set] = {}
        for _hunk in parsed.hunks:
            if _hunk.file_path not in valid_lines_per_file:
                valid_lines_per_file[_hunk.file_path] = set()
            for _ln, _ in _hunk.new_file_lines():
                valid_lines_per_file[_hunk.file_path].add(_ln)

        pr_files: set = set(valid_lines_per_file.keys())

        _total_before = len(inline_comments)
        _skipped = 0
        validated_comments: List[InlineComment] = []

        for _c in inline_comments:
            # Guard 1: file must be in the PR diff
            if _c.path not in pr_files:
                logger.warning(
                    "Validation: skipping comment — file not in PR diff: %s", _c.path
                )
                _skipped += 1
                continue

            _valid_lines = valid_lines_per_file[_c.path]

            # Guard 2: file has no valid lines (edge case — empty hunk)
            if not _valid_lines:
                logger.warning(
                    "Validation: skipping comment — no valid lines for file: %s", _c.path
                )
                _skipped += 1
                continue

            # Guard 3: line number must be in the diff; fix it to nearest valid line
            if _c.line not in _valid_lines:
                _old_line = _c.line
                _c.line = min(_valid_lines)
                logger.info(
                    "Validation: fixed line %d → %d for %s", _old_line, _c.line, _c.path
                )

            validated_comments.append(_c)

        _total_after = len(validated_comments)
        logger.info(
            "Safety validation: %d comments → %d after validation (%d skipped)",
            _total_before, _total_after, _skipped,
        )

        inline_comments = validated_comments

        # ── Step 6: Post inline comments via GitHub Review API ─────────────────
        if inline_comments:
            critical_count = sum(1 for c in inline_comments if c.severity == "critical")
            high_count = sum(1 for c in inline_comments if c.severity == "high")
            medium_count = sum(1 for c in inline_comments if c.severity == "medium")

            review_body = _build_review_summary(
                ctx=ctx,
                total=len(inline_comments),
                critical=critical_count,
                high=high_count,
                medium=medium_count,
                was_truncated=was_truncated,
            )

            # Split into batches of 50 — GitHub Review API has a per-review comment limit
            for i, batch in enumerate(_batch(inline_comments, size=50)):
                github.post_pr_review(
                    repo=ctx.repo,
                    pr_number=ctx.pr_number,
                    commit_id=ctx.head_sha,
                    comments=batch,
                    body=review_body if i == 0 else "",
                    event="COMMENT",
                )
            logger.info("✅ Review complete for PR %s#%d", ctx.repo, ctx.pr_number)

        else:
            github.post_pr_review(
                repo=ctx.repo,
                pr_number=ctx.pr_number,
                commit_id=ctx.head_sha,
                comments=[],
                body="✅ **ph AI Review**: No issues found. Looks good! 🎉",
                event="COMMENT",
            )
            logger.info("✅ Clean review for PR %s#%d", ctx.repo, ctx.pr_number)

    except httpx.HTTPStatusError as exc:
        logger.error(
            "GitHub API error for PR %s#%d: HTTP %d — %s",
            ctx.repo, ctx.pr_number,
            exc.response.status_code, exc.response.text[:300],
        )
    except Exception:
        logger.error(
            "Unhandled error processing PR %s#%d:\n%s",
            ctx.repo, ctx.pr_number, traceback.format_exc(),
        )


def run_structure_review(ctx: PRContext, agent: StructureAgent) -> None:
    """
    Run the Gemini-powered structure agent in a ThreadPoolExecutor worker thread.
    Catches all exceptions so one bad PR cannot crash the worker pool.

    Args:
        ctx:   Immutable PR context (repo, number, head SHA)
        agent: Shared StructureAgent instance (thread-safe for concurrent reads)
    """
    try:
        logger.info("▶ Structure review starting: %s#%d", ctx.repo, ctx.pr_number)
        issues = agent.review_pr(ctx.repo, ctx.pr_number, ctx.head_sha)
        logger.info(
            "✅ Structure review done: %s#%d — %d issues",
            ctx.repo, ctx.pr_number, len(issues),
        )
    except Exception:
        logger.error(
            "Structure review failed for %s#%d:\n%s",
            ctx.repo, ctx.pr_number, traceback.format_exc(),
        )


def _build_review_summary(
    ctx: PRContext,
    total: int,
    critical: int,
    high: int,
    medium: int,
    was_truncated: bool,
) -> str:
    """
    Build the top-level Markdown body for the GitHub PR Review.
    This appears as the review summary above the inline comments.
    """
    lines = [
        f"## 🤖 ph AI Review — {ctx.pr_title}",
        "",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🚨 Critical | {critical} |",
        f"| 🔴 High     | {high} |",
        f"| 🟡 Medium   | {medium} |",
        f"| **Total**   | **{total}** |",
        "",
    ]
    if was_truncated:
        lines.append(
            "> ⚠️ **Note:** Diff was truncated due to size — only the first portion was reviewed."
        )
    lines += [
        "",
        "_Inline comments below. Apply suggestions with one click where available._",
        "",
        "---",
        "_Powered by [ph](https://github.com/your-org/ph)_",
    ]
    return "\n".join(lines)


def _batch(items: List[Any], size: int) -> List[List[Any]]:
    """Split a list into chunks of at most `size` elements."""
    return [items[i : i + size] for i in range(0, len(items), size)]


# ─────────────────────────────────────────────────────────────────────────────
# Application Lifecycle
# ─────────────────────────────────────────────────────────────────────────────

# Module-level shared resources — initialised in lifespan, cleaned up on shutdown.
_executor: Optional[ThreadPoolExecutor] = None
_github_client: Optional[GitHubClient] = None
_structure_agent: Optional[StructureAgent] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan manager (replaces deprecated @app.on_event).
    Everything before `yield` runs at startup; everything after at shutdown.
    """
    global _executor, _github_client, _structure_agent

    logger.info("🚀 Starting ph webhook server…")
    _executor = ThreadPoolExecutor(
        max_workers=MAX_WORKERS,
        thread_name_prefix="pr-review",
    )
    _github_client = GitHubClient(token=GITHUB_TOKEN)
    _structure_agent = StructureAgent()
    logger.info(
        "Ready | workers=%d | inline=%s | security_scan=%s | api=%s",
        MAX_WORKERS, ENABLE_INLINE_COMMENTS, ENABLE_SECURITY_SCAN, GITHUB_API_BASE,
    )

    yield  # ← server is running here

    logger.info("🛑 Shutting down — draining in-flight PR jobs…")
    if _executor:
        _executor.shutdown(wait=True)
    if _github_client:
        _github_client.close()
    if _structure_agent:
        _structure_agent.close()
    logger.info("Shutdown complete.")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ph Webhook",
    description="GitHub PR webhook receiver with AI-powered inline code review",
    version="2.0.0",
    lifespan=lifespan,
    # Uncomment in production to remove API docs (reduce attack surface):
    # docs_url=None, redoc_url=None,
)


@app.get("/health", tags=["ops"])
async def health_check() -> Dict[str, str]:
    """
    Liveness probe — used by Render, Railway, Fly.io, and Kubernetes.
    Returns minimal info: no secrets, no internal state.
    """
    return {"status": "ok", "service": "ph-webhook", "version": "2.0.0"}


@app.post("/webhook", tags=["webhook"])
async def webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(default=None),
    x_github_event: Optional[str] = Header(default=None),
    x_github_delivery: Optional[str] = Header(default=None),
) -> JSONResponse:
    """
    Receive GitHub webhook events and dispatch background review jobs.

    Flow:
      1. Read raw body bytes (BEFORE JSON parsing — needed for HMAC)
      2. Verify X-Hub-Signature-256
      3. Parse JSON
      4. Route: pull_request/opened|synchronize → dispatch both review agents
                ping                            → acknowledge
                anything else                   → ignore
      5. Return 200 immediately (GitHub times out at 10s)

    IMPORTANT: Never perform blocking work (HTTP calls, LLM inference) inside
    this handler. Always dispatch to the ThreadPoolExecutor.
    """
    logger.info(
        "Webhook | event=%s | delivery=%s",
        x_github_event or "?", x_github_delivery or "?",
    )

    # ── Step 1: Read raw bytes ─────────────────────────────────────────────────
    raw_body: bytes = await request.body()

    # ── Step 2: Verify HMAC signature ─────────────────────────────────────────
    verify_github_signature(raw_body, x_hub_signature_256)

    # ── Step 3: Parse JSON ─────────────────────────────────────────────────────
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JSON payload: {exc}",
        ) from exc

    action: str = payload.get("action", "")
    logger.info("Event: %s / action: %s", x_github_event, action)

    # ── Step 4: Route ──────────────────────────────────────────────────────────

    if x_github_event == "pull_request" and action in ("opened", "synchronize", "reopened"):
        try:
            ctx = PRContext.from_payload(payload)
        except ValueError as exc:
            logger.error("Malformed payload: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        if _executor and _github_client and _structure_agent:
            # Agent 1: Code quality + security review (ai_agent.py / MegaLLM)
            # One MegaLLM instance per job — conversation_history is not thread-safe
            llm = MegaLLM()
            _executor.submit(process_pr, ctx, _github_client, llm)

            # Agent 2: Repo structure review (structure_agent.py / Gemini)
            _executor.submit(run_structure_review, ctx, _structure_agent)

            logger.info(
                "PR %s#%d queued for code + structure review (action=%s)",
                ctx.repo, ctx.pr_number, action,
            )
        else:
            logger.error("Executor or clients not ready — dropping event")

    elif x_github_event == "ping":
        logger.info("GitHub ping ✓ (zen: %s)", payload.get("zen", "—"))

    else:
        logger.debug("Ignored event: %s/%s", x_github_event, action)

    # Always return 200 — never let GitHub mark the delivery as failed
    return JSONResponse(content={"status": "ok"}, status_code=status.HTTP_200_OK)


# ─────────────────────────────────────────────────────────────────────────────
# Dev entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=True,
        log_level="info",
    )