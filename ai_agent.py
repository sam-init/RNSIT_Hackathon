#!/usr/bin/env python3
"""
ph - Codebase Health Score & AI Assistant
==========================================
Core analysis modules (M-01 to M-08) with weighted health scoring.
AI features (ask, review, brief, chat, fix) powered by MegaLLM backend.

Usage:
    python ph.py                    # Interactive chat mode
    python ph.py ask "question"     # Single question
    python ph.py review <diff_file> # Review a PR diff
    python ph.py brief              # Generate onboarding doc
"""

from __future__ import annotations  # Enable postponed evaluation of annotations (PEP 563)

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
import tempfile
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, Generator, List, Optional, Tuple, TypeVar

import requests
import yaml

# ─────────────────────────────────────────────────────────────────────────────
# Configuration & Constants
# ─────────────────────────────────────────────────────────────────────────────

# Persistent cache directory for expensive analysis results
CACHE_DIR = Path(".ph-cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)  # parents=True handles nested paths

# LLM backend configuration — override via environment variables for flexibility
DEFAULT_LLM_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
LLM_API_KEY: Optional[str] = os.getenv("LLM_API_KEY")        # None = unauthenticated (local models)
LLM_ENDPOINT: str = os.getenv("PH_LLM_ENDPOINT", DEFAULT_LLM_ENDPOINT)
LLM_MODEL: str = os.getenv("PH_LLM_MODEL", "meta/llama-3.1-8b-instruct")
LLM_TIMEOUT: int = int(os.getenv("PH_LLM_TIMEOUT", "30"))     # seconds before giving up
LLM_MAX_TOKENS: int = int(os.getenv("PH_LLM_MAX_TOKENS", "1024"))  # cap on LLM response size
LLM_TEMPERATURE: float = float(os.getenv("PH_LLM_TEMPERATURE", "0.7"))  # 0=deterministic, 1=creative

# Score bands — used to bucket the final health percentage into human-readable tiers
SCORE_BANDS: List[Tuple[str, int, int]] = [
    ("EXCELLENT",  90, 100),
    ("GOOD",       75,  89),
    ("MODERATE",   60,  74),
    ("HIGH_RISK",  40,  59),
    ("CRITICAL",    0,  39),
]

# Module weights must sum to 1.0 — higher weight = bigger impact on final score
MODULE_WEIGHTS: Dict[str, float] = {
    "M-05": 0.20,  # Dependency Security     — CVEs, pinned versions
    "M-02": 0.18,  # Code Quality            — lint, complexity, duplication
    "M-01": 0.15,  # CI/CD Pipeline          — pipeline health, failure rate
    "M-04": 0.14,  # Test Flakiness          — flaky test detection
    "M-07": 0.13,  # Env Integrity           — .env consistency, secrets hygiene
    "M-08": 0.10,  # Build Performance       — build time trends
    "M-03": 0.06,  # Docs Freshness          — stale READMEs, missing docstrings
    "M-06": 0.04,  # PR Complexity           — large diff detection
}

# Validate weight sum at import time — catch misconfiguration early
_weight_total = round(sum(MODULE_WEIGHTS.values()), 10)
assert _weight_total == 1.0, f"MODULE_WEIGHTS must sum to 1.0, got {_weight_total}"

# ─────────────────────────────────────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────────────────────────────────────

# Use a structured log format: timestamp, level, caller module, message
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stderr)],  # stderr keeps stdout clean for piping
)
logger = logging.getLogger("ph")

# ─────────────────────────────────────────────────────────────────────────────
# Type Aliases
# ─────────────────────────────────────────────────────────────────────────────

Message = Dict[str, str]          # {"role": "user"|"assistant"|"system", "content": str}
Finding = Dict[str, Any]          # {"description": str, "severity": str, "file": str, ...}
RepoInfo = Dict[str, Any]         # Freeform repo metadata gathered by analysis modules

F = TypeVar("F", bound=Callable[..., Any])  # Generic function type for decorators

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ModuleResult:
    """
    Holds the output of a single analysis module (M-01 to M-08).
    score: 0–100 (module-local), weighted externally by MODULE_WEIGHTS
    findings: list of individual issues detected
    metadata: freeform extra context (e.g., number of tests run, tool version)
    """
    module_id: str
    score: float                             # 0–100, NOT yet weighted
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    ran_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def weighted_score(self) -> float:
        """Apply this module's weight to produce its contribution to the global score."""
        weight = MODULE_WEIGHTS.get(self.module_id, 0.0)
        return self.score * weight


@dataclass
class HealthReport:
    """
    Aggregates all ModuleResult objects into a single project health snapshot.
    final_score is the dot product of (module_scores × module_weights).
    """
    module_results: Dict[str, ModuleResult] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def final_score(self) -> float:
        """Weighted sum of all module scores, clamped to [0, 100]."""
        return min(100.0, max(0.0, sum(
            r.weighted_score() for r in self.module_results.values()
        )))

    @property
    def band(self) -> str:
        """Return the human-readable health tier for the final score."""
        s = self.final_score
        for label, lo, hi in SCORE_BANDS:
            if lo <= s <= hi:
                return label
        return "UNKNOWN"  # Should never happen if SCORE_BANDS covers [0, 100]

    def to_dict(self) -> Dict[str, Any]:
        """Serialise to a plain dict (safe for JSON / YAML export)."""
        return {
            "generated_at": self.generated_at.isoformat(),
            "final_score": round(self.final_score, 2),
            "band": self.band,
            "modules": {
                mid: {
                    "score": r.score,
                    "weighted_contribution": round(r.weighted_score(), 4),
                    "findings_count": len(r.findings),
                    "findings": r.findings,
                    "metadata": r.metadata,
                }
                for mid, r in self.module_results.items()
            },
        }


# ─────────────────────────────────────────────────────────────────────────────
# Helper Utilities
# ─────────────────────────────────────────────────────────────────────────────

def cache_key(data: Any) -> str:
    """
    Deterministic SHA-256 hex digest for any JSON-serialisable value.
    sort_keys=True ensures dicts with the same contents but different insertion
    order produce the same key (Python dict ordering is insertion-order since 3.7).
    """
    payload = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def disk_cache(ttl_seconds: int = 3600) -> Callable[[F], F]:
    """
    Decorator factory that persists function results as JSON files in CACHE_DIR.

    Args:
        ttl_seconds: Cache lifetime in seconds. 0 = never expire.

    Why JSON (not pickle)?  JSON is human-readable, debuggable, and safe to
    deserialise from untrusted sources.  Pickle is faster but is a code
    execution vector if the cache is tampered with.
    """
    def decorator(func: F) -> F:
        @wraps(func)  # Preserve __name__, __doc__, etc.
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key_data = {"func": func.__name__, "args": args, "kwargs": kwargs}
            key = cache_key(key_data)
            cache_file = CACHE_DIR / f"{key}.json"

            # Check cache validity
            if cache_file.exists():
                age = time.time() - cache_file.stat().st_mtime
                if ttl_seconds == 0 or age < ttl_seconds:
                    logger.debug("Cache hit for %s (age=%.0fs)", func.__name__, age)
                    with cache_file.open("r", encoding="utf-8") as f:
                        return json.load(f)
                else:
                    logger.debug("Cache expired for %s (age=%.0fs)", func.__name__, age)

            result = func(*args, **kwargs)

            # Persist result; write to a temp file first to avoid partial writes
            # (atomic rename pattern — POSIX only, acceptable for a dev tool)
            tmp = cache_file.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(result, f, default=str, indent=2)
            tmp.replace(cache_file)

            return result
        return wrapper  # type: ignore[return-value]
    return decorator


def run_cmd(
    cmd: List[str],
    cwd: Optional[Path] = None,
    env_extra: Optional[Dict[str, str]] = None,
) -> Tuple[str, str, int]:
    """
    Execute a subprocess and return (stdout, stderr, returncode).

    Args:
        cmd:        Command + arguments as a list (no shell=True to prevent injection).
        cwd:        Working directory; defaults to the current working directory.
        env_extra:  Extra environment variables to inject alongside os.environ.

    Returns a tuple rather than raising so callers can decide how to handle failures.
    Using check=False intentionally — many tools (flake8, pytest, etc.) use non-zero
    exit codes to signal findings, not errors.
    """
    env = {**os.environ, **(env_extra or {})}  # Merge without mutating os.environ
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd or Path.cwd()),
            capture_output=True,
            text=True,
            check=False,     # Never raise on non-zero; let callers decide
            env=env,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        # The executable wasn't found — return a structured error instead of crashing
        logger.warning("Command not found: %s", cmd[0])
        return "", f"Command not found: {cmd[0]}", -1
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error running %s: %s", cmd, exc)
        return "", str(exc), -1


# ─────────────────────────────────────────────────────────────────────────────
# LLM Client (MegaLLM)
# ─────────────────────────────────────────────────────────────────────────────

class MegaLLM:
    """
    Pluggable LLM client.

    Design goals:
    - Works against any OpenAI-compatible /v1/chat/completions endpoint
      (NVIDIA NIM, Ollama, vLLM, Together AI, etc.)
    - Stateful for multi-turn chat via conversation_history
    - Stateless for single-shot calls (ask, review, brief, fix)
    - Retry logic with exponential back-off for transient API failures
    """

    # System prompt injected into every conversation — sets tone and constraints
    DEFAULT_SYSTEM_PROMPT = (
        "You are ph, a senior software engineer and code quality expert. "
        "Be concise, precise, and actionable. "
        "Reference file names and line numbers when available. "
        "Prioritise security and correctness over style."
    )

    def __init__(
        self,
        endpoint: str = LLM_ENDPOINT,
        api_key: Optional[str] = LLM_API_KEY,
        model: str = LLM_MODEL,
        system_prompt: Optional[str] = None,
        max_retries: int = 3,
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.system_prompt = system_prompt or self.DEFAULT_SYSTEM_PROMPT
        self.max_retries = max_retries
        self.conversation_history: List[Message] = []  # Persists across chat() calls

    # ── Internal ──────────────────────────────────────────────────────────────

    def _build_headers(self) -> Dict[str, str]:
        """Construct HTTP headers; omit Authorization if no key is set (local models)."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _call_api(self, messages: List[Message], stream: bool = False) -> str:
        """
        POST to the LLM endpoint and return the assistant's reply as a string.

        Implements exponential back-off retry for 429 (rate limit) and 5xx errors.
        stream=True is accepted as a parameter but not yet implemented — placeholder
        for future streaming support (useful for long outputs like brief generation).
        """
        # Prepend the system prompt to every API call so it's always in context
        full_messages: List[Message] = [
            {"role": "system", "content": self.system_prompt},
            *messages,
        ]

        payload = {
            "model": self.model,
            "messages": full_messages,
            "temperature": LLM_TEMPERATURE,
            "max_tokens": LLM_MAX_TOKENS,
        }

        last_exc: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                resp = requests.post(
                    self.endpoint,
                    headers=self._build_headers(),
                    json=payload,
                    timeout=LLM_TIMEOUT,
                )

                # Raise for 4xx/5xx before parsing JSON
                resp.raise_for_status()

                data = resp.json()

                # Validate expected shape — API versions can differ subtly
                if "choices" not in data or not data["choices"]:
                    raise ValueError(f"Unexpected API response shape: {list(data.keys())}")

                return data["choices"][0]["message"]["content"]

            except requests.exceptions.Timeout:
                logger.warning("LLM request timed out (attempt %d/%d)", attempt, self.max_retries)
                last_exc = TimeoutError("LLM request timed out")

            except requests.exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response else "?"
                logger.warning("HTTP %s from LLM (attempt %d/%d)", status, attempt, self.max_retries)
                last_exc = exc
                # Don't retry on client errors (except 429 rate-limit)
                if exc.response and 400 <= exc.response.status_code < 500 and exc.response.status_code != 429:
                    break

            except Exception as exc:  # noqa: BLE001
                logger.warning("LLM call failed (attempt %d/%d): %s", attempt, self.max_retries, exc)
                last_exc = exc

            # Exponential back-off: 1s, 2s, 4s …
            if attempt < self.max_retries:
                sleep_time = 2 ** (attempt - 1)
                logger.info("Retrying in %ds…", sleep_time)
                time.sleep(sleep_time)

        # All retries exhausted — return a structured error string so callers
        # can display it gracefully rather than crashing
        error_msg = f"[LLM unavailable after {self.max_retries} attempts: {last_exc}]"
        logger.error(error_msg)
        return error_msg

    # ── Public API ────────────────────────────────────────────────────────────

    def ask(self, prompt: str, context: Optional[str] = None) -> str:
        """
        Single-turn question.  Optionally inject grounded codebase context so the
        LLM can reference real file content rather than hallucinating.

        Args:
            prompt:  The user question.
            context: Raw text extracted from the codebase (e.g., file contents,
                     grep output) prepended to the prompt as grounding.
        """
        if context:
            # Delimit the context clearly so the model doesn't confuse it with the question
            full_prompt = (
                f"<codebase_context>\n{context}\n</codebase_context>\n\n"
                f"Question: {prompt}"
            )
        else:
            full_prompt = prompt

        return self._call_api([{"role": "user", "content": full_prompt}])

    def review(self, diff: str, test_coverage: Optional[str] = None) -> str:
        """
        Code-review a unified diff.

        Structured prompt forces the model to output findings in a consistent
        format that can later be parsed into Finding dicts if needed.

        Args:
            diff:          Output of `git diff` or similar.
            test_coverage: Coverage report snippet (e.g., pytest-cov output).
        """
        coverage_block = (
            f"<test_coverage>\n{test_coverage}\n</test_coverage>"
            if test_coverage
            else "<!-- No coverage data provided -->"
        )

        prompt = f"""You are performing a code review. Output findings in this format:

FINDING [SEVERITY: HIGH|MEDIUM|LOW] [FILE: path] [LINE: N]
<one-sentence description>
SUGGESTION: <concrete fix>
---

Review the following diff. Focus on: bugs, security vulnerabilities,
untested code paths, and complexity spikes.

{coverage_block}

<diff>
{diff}
</diff>"""

        return self._call_api([{"role": "user", "content": prompt}])

    def brief(self, repo_info: RepoInfo) -> str:
        """
        Generate an ONBOARDING.md for new contributors.

        Takes structured repo_info (populated by analysis modules) and produces
        a Markdown document with architecture overview, setup steps, and owner map.
        """
        # Format repo_info as indented YAML for readability inside the prompt
        repo_yaml = yaml.dump(repo_info, default_flow_style=False, sort_keys=True)

        prompt = f"""Generate a complete ONBOARDING.md based on the repository analysis below.

Include these sections:
1. Project Overview (2–3 sentences)
2. Architecture Summary (key components and their relationships)
3. Getting Started (setup commands, prerequisites)
4. Key Entry Points (files a new engineer should read first)
5. Ownership Map (team/module ownership)
6. Health Status (score, top issues to fix)

Be concise and actionable. Use Markdown headings, bullet points, and code blocks.

<repo_analysis>
{repo_yaml}
</repo_analysis>"""

        return self._call_api([{"role": "user", "content": prompt}])

    def chat(self, user_input: str) -> str:
        """
        Multi-turn conversational assistant.

        conversation_history accumulates across calls within the same MegaLLM
        instance — suitable for a single interactive session.  To start a new
        conversation, call reset_chat() or instantiate a new MegaLLM.
        """
        self.conversation_history.append({"role": "user", "content": user_input})
        response = self._call_api(self.conversation_history)
        self.conversation_history.append({"role": "assistant", "content": response})
        return response

    def reset_chat(self) -> None:
        """Clear conversation history to start a fresh session."""
        self.conversation_history.clear()
        logger.debug("Chat history cleared.")

    def generate_fix(self, finding: Finding, code_snippet: str) -> str:
        """
        Generate a unified diff patch for a specific code quality finding.

        The model is explicitly asked for a diff (not prose) so the output can
        be piped directly to `git apply` or displayed in a diff viewer.

        Args:
            finding:      A Finding dict with at minimum a 'description' key.
            code_snippet: The raw source code surrounding the issue.
        """
        prompt = f"""Produce a unified diff patch that fixes the issue below.
Output ONLY the diff — no explanations, no backticks, no preamble.

Finding:
  Description : {finding.get("description", "N/A")}
  Severity    : {finding.get("severity", "medium")}
  File        : {finding.get("file", "unknown")}
  Line        : {finding.get("line", "N/A")}

Original code:
{code_snippet}"""

        return self._call_api([{"role": "user", "content": prompt}])

    # ── Convenience ───────────────────────────────────────────────────────────

    def summarise_findings(self, findings: List[Finding]) -> str:
        """
        Produce a terse executive summary of a list of findings.
        Useful for PR comments or Slack notifications.
        """
        if not findings:
            return "No findings to summarise."

        findings_yaml = yaml.dump(findings, default_flow_style=False)
        prompt = (
            f"Summarise these code findings in 3–5 bullet points for a non-technical "
            f"manager. Group by severity.\n\n{findings_yaml}"
        )
        return self._call_api([{"role": "user", "content": prompt}])


# ─────────────────────────────────────────────────────────────────────────────
# Score Utilities
# ─────────────────────────────────────────────────────────────────────────────

def score_band(score: float) -> str:
    """Return the human-readable band label for a 0–100 score."""
    for label, lo, hi in SCORE_BANDS:
        if lo <= score <= hi:
            return label
    return "UNKNOWN"


def print_health_report(report: HealthReport) -> None:
    """Pretty-print a HealthReport to stdout."""
    bar_width = 40
    filled = int(report.final_score / 100 * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)

    print(f"\n{'─' * 60}")
    print(f"  Codebase Health Score: {report.final_score:.1f}/100  [{report.band}]")
    print(f"  [{bar}]")
    print(f"{'─' * 60}")
    for mid, result in sorted(report.module_results.items()):
        icon = "✅" if result.score >= 75 else "⚠️ " if result.score >= 50 else "❌"
        print(f"  {icon}  {mid}  {result.score:6.1f}  ({len(result.findings)} findings)")
    print(f"{'─' * 60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI Entry Point
# ─────────────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    """Construct and return the argument parser (kept separate for testability)."""
    parser = argparse.ArgumentParser(
        prog="ph",
        description="Codebase Health Score & AI Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # ph ask "why is auth broken?"
    ask_p = sub.add_parser("ask", help="Ask a one-shot question about the codebase")
    ask_p.add_argument("question", nargs="+", help="Question text")
    ask_p.add_argument("--context-file", metavar="FILE", help="File to inject as context")

    # ph review path/to/file.diff
    rev_p = sub.add_parser("review", help="AI-powered code review of a diff")
    rev_p.add_argument("diff_file", metavar="DIFF", help="Path to a unified diff file")
    rev_p.add_argument("--coverage", metavar="FILE", help="Optional coverage report")

    # ph brief
    sub.add_parser("brief", help="Generate ONBOARDING.md for new contributors")

    # ph fix
    fix_p = sub.add_parser("fix", help="Generate a patch for a finding (JSON input)")
    fix_p.add_argument("finding_json", metavar="JSON", help="Finding as a JSON string")
    fix_p.add_argument("snippet_file", metavar="FILE", help="File containing the code snippet")

    # ph chat (default — no subcommand)
    sub.add_parser("chat", help="Persistent multi-turn chat (default)")

    return parser


def main() -> int:
    """
    CLI dispatch.  Returns an exit code (0 = success, non-zero = error).
    Keeping main() thin — real logic lives in MegaLLM methods.
    """
    parser = build_cli()
    args = parser.parse_args()
    llm = MegaLLM()

    try:
        if args.command == "ask":
            context: Optional[str] = None
            if args.context_file:
                context = Path(args.context_file).read_text(encoding="utf-8")
            print(llm.ask(" ".join(args.question), context=context))

        elif args.command == "review":
            diff = Path(args.diff_file).read_text(encoding="utf-8")
            coverage: Optional[str] = None
            if args.coverage:
                coverage = Path(args.coverage).read_text(encoding="utf-8")
            print(llm.review(diff, test_coverage=coverage))

        elif args.command == "brief":
            # In a full implementation, analysis modules would populate repo_info
            repo_info: RepoInfo = {
                "architecture": "Monorepo",
                "entry_points": ["ph.py"],
                "owners": {},
                "tech_stack": ["Python 3.11", "FastAPI", "requests"],
                "health_score": "N/A — run full scan first",
            }
            print(llm.brief(repo_info))

        elif args.command == "fix":
            finding = json.loads(args.finding_json)
            snippet = Path(args.snippet_file).read_text(encoding="utf-8")
            print(llm.generate_fix(finding, snippet))

        else:
            # Default: interactive multi-turn chat
            print("ph AI Assistant — type 'exit' or Ctrl-C to quit.\n")
            while True:
                try:
                    user_input = input("You: ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nBye!")
                    break

                if not user_input:
                    continue  # Skip empty lines silently

                if user_input.lower() in {"exit", "quit", "bye"}:
                    print("Exiting.")
                    break

                if user_input.lower() == "/reset":
                    llm.reset_chat()
                    print("[Chat history cleared]\n")
                    continue

                response = llm.chat(user_input)
                print(f"\nph: {response}\n")

    except FileNotFoundError as exc:
        logger.error("File not found: %s", exc)
        return 1
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON: %s", exc)
        return 1
    except Exception as exc:  # noqa: BLE001
        logger.error("Unhandled error: %s\n%s", exc, traceback.format_exc())
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())