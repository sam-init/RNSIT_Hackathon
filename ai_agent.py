#!/usr/bin/env python3
"""
ai_agent.py — ph Codebase Health Score & AI Review Engine
===========================================================

Core analysis modules (M-01 to M-08) with weighted health scoring.
AI features: ask, review (with INLINE COMMENTS), brief, chat, fix, security scan.

New in this version:
  - InlineComment dataclass  → maps findings to exact file + line positions
  - DiffParser               → converts unified diff text into reviewable hunks
  - SecurityScanner          → pattern-based pre-scan (secrets, sqli, xss, path traversal…)
  - MegaLLM.review_inline()  → returns List[InlineComment] ready for GitHub Review API
  - MegaLLM.security_audit() → deep security analysis returning structured findings

Usage:
    python ai_agent.py                       # interactive chat
    python ai_agent.py ask "why is X slow"
    python ai_agent.py review my.diff
    python ai_agent.py security my.diff      # security-only scan
    python ai_agent.py brief
    python ai_agent.py fix '{"description":"..."}' snippet.py
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
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

CACHE_DIR = Path(".ph-cache")
CACHE_DIR.mkdir(parents=True, exist_ok=True)

DEFAULT_LLM_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
LLM_API_KEY: Optional[str] = os.getenv("LLM_API_KEY")
LLM_ENDPOINT: str = os.getenv("PH_LLM_ENDPOINT", DEFAULT_LLM_ENDPOINT)
LLM_MODEL: str = os.getenv("PH_LLM_MODEL", "meta/llama-3.1-8b-instruct")
LLM_TIMEOUT: int = int(os.getenv("PH_LLM_TIMEOUT", "60"))        # longer timeout for review jobs
LLM_MAX_TOKENS: int = int(os.getenv("PH_LLM_MAX_TOKENS", "2048")) # more tokens for inline reviews
LLM_TEMPERATURE: float = float(os.getenv("PH_LLM_TEMPERATURE", "0.2"))  # lower = more precise/less creative

# Score bands
SCORE_BANDS: List[Tuple[str, int, int]] = [
    ("EXCELLENT",  90, 100),
    ("GOOD",       75,  89),
    ("MODERATE",   60,  74),
    ("HIGH_RISK",  40,  59),
    ("CRITICAL",    0,  39),
]

MODULE_WEIGHTS: Dict[str, float] = {
    "M-05": 0.20,  # Dependency Security
    "M-02": 0.18,  # Code Quality
    "M-01": 0.15,  # CI/CD Pipeline
    "M-04": 0.14,  # Test Flakiness
    "M-07": 0.13,  # Env Integrity
    "M-08": 0.10,  # Build Performance
    "M-03": 0.06,  # Docs Freshness
    "M-06": 0.04,  # PR Complexity
}

_weight_total = round(sum(MODULE_WEIGHTS.values()), 10)
assert _weight_total == 1.0, f"MODULE_WEIGHTS must sum to 1.0, got {_weight_total}"

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stderr)],
)
logger = logging.getLogger("ph")

# ─────────────────────────────────────────────────────────────────────────────
# Type Aliases
# ─────────────────────────────────────────────────────────────────────────────

Message = Dict[str, str]
Finding = Dict[str, Any]
RepoInfo = Dict[str, Any]
F = TypeVar("F", bound=Callable[..., Any])

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InlineComment:
    """
    Represents a single inline review comment to be posted via the GitHub
    Pull Request Review API (POST /repos/{owner}/{repo}/pulls/{pr}/reviews).

    GitHub's Review API requires:
      - path:        repo-relative file path (e.g. "src/auth.py")
      - position:    line position within the diff hunk (1-indexed from hunk start)
                     OR use line/side for the newer multi-line comment API
      - body:        Markdown-formatted comment text

    side: "RIGHT" = new file (added lines), "LEFT" = old file (deleted lines)
    severity: "critical" | "high" | "medium" | "low" | "info"
    category: "bug" | "security" | "style" | "performance" | "architecture" | "test"
    suggestion: optional one-liner code suggestion (rendered as a GitHub suggestion block)
    """
    path: str
    line: int                         # line number in the NEW file
    body: str                         # Markdown-formatted comment
    severity: str = "medium"
    category: str = "bug"
    side: str = "RIGHT"               # RIGHT = new file lines (default for added code)
    suggestion: Optional[str] = None  # if set, will be wrapped in a ```suggestion block
    diff_hunk: str = ""               # the raw diff hunk for context (not posted to GitHub)

    def to_github_payload(self) -> Dict[str, Any]:
        """
        Serialise to the shape expected by:
        POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews
        (part of the 'comments' array in the review body)

        If a suggestion is provided, it's injected as a GitHub suggestion block
        so reviewers can apply it with a single click.
        """
        # Wrap inline code suggestion in GitHub's special syntax
        body = self.body
        if self.suggestion:
            body += f"\n\n```suggestion\n{self.suggestion}\n```"

        return {
            "path": self.path,
            "line": self.line,
            "side": self.side,
            "body": body,
        }

    def to_dict(self) -> Dict[str, Any]:
        """Full serialisation including internal fields (for logging / export)."""
        return {
            "path": self.path,
            "line": self.line,
            "side": self.side,
            "severity": self.severity,
            "category": self.category,
            "body": self.body,
            "suggestion": self.suggestion,
        }


@dataclass
class DiffHunk:
    """
    Represents one hunk from a unified diff — the block starting with @@.

    A unified diff hunk header looks like:
        @@ -10,7 +15,12 @@ def foo():
                ^    ^   ^    ^
                |    |   |    lines in new file
                |    |   start line in new file
                |    lines in old file
                start line in old file

    We track the new-file line numbers because GitHub inline comments
    are anchored to the new file's line numbers.
    """
    file_path: str
    old_start: int      # starting line in the old (a/) file
    old_count: int      # number of lines from the old file
    new_start: int      # starting line in the new (b/) file  ← what GitHub uses
    new_count: int      # number of lines in the new file
    lines: List[str]    # raw diff lines (+/-/ ) within this hunk
    context: str = ""   # optional function/class context from the @@ header (e.g. "def foo():")

    def new_file_lines(self) -> List[Tuple[int, str]]:
        """
        Yield (absolute_new_line_number, line_content) for every line that
        appears in the NEW file (lines starting with '+' or ' ').
        Lines starting with '-' were deleted and have no new-file line number.
        """
        line_no = self.new_start
        result = []
        for raw in self.lines:
            if raw.startswith("-"):
                continue           # deleted line: no new-file line number
            result.append((line_no, raw))
            line_no += 1
        return result


@dataclass
class ParsedDiff:
    """
    Complete parsed representation of a unified diff.
    Contains all DiffHunks grouped by file.
    """
    hunks: List[DiffHunk] = field(default_factory=list)

    @property
    def files(self) -> List[str]:
        """Unique list of files touched by this diff."""
        seen = set()
        return [h.file_path for h in self.hunks if h.file_path not in seen and not seen.add(h.file_path)]  # type: ignore[func-returns-value]

    def hunks_for_file(self, path: str) -> List[DiffHunk]:
        return [h for h in self.hunks if h.file_path == path]


@dataclass
class ModuleResult:
    """Output of a single analysis module (M-01 to M-08)."""
    module_id: str
    score: float
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    ran_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def weighted_score(self) -> float:
        return self.score * MODULE_WEIGHTS.get(self.module_id, 0.0)


@dataclass
class HealthReport:
    """Aggregated project health snapshot."""
    module_results: Dict[str, ModuleResult] = field(default_factory=dict)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def final_score(self) -> float:
        return min(100.0, max(0.0, sum(r.weighted_score() for r in self.module_results.values())))

    @property
    def band(self) -> str:
        s = self.final_score
        for label, lo, hi in SCORE_BANDS:
            if lo <= s <= hi:
                return label
        return "UNKNOWN"

    def to_dict(self) -> Dict[str, Any]:
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
# Diff Parser
# ─────────────────────────────────────────────────────────────────────────────

class DiffParser:
    """
    Parses a unified diff (output of `git diff`) into structured DiffHunk objects.

    The parser is line-by-line and handles:
      - Multiple files in a single diff
      - Multiple hunks per file
      - Hunk context lines (function/class name after the @@...@@ marker)
      - Renamed files (--- a/old +++ b/new)

    Example unified diff structure:
        diff --git a/src/auth.py b/src/auth.py
        --- a/src/auth.py
        +++ b/src/auth.py
        @@ -10,5 +10,8 @@ class Auth:
         context line
        -deleted line
        +added line
    """

    # Regex for the hunk header: @@ -old_start,old_count +new_start,new_count @@ context
    # The ,count parts are optional (git omits them when count=1)
    _HUNK_RE = re.compile(
        r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)?$"
    )

    # Match "diff --git a/path b/path" or "--- a/path" / "+++ b/path"
    _FILE_RE = re.compile(r"^\+\+\+ b/(.+)$")

    @classmethod
    def parse(cls, diff_text: str) -> ParsedDiff:
        """
        Parse a full unified diff string into a ParsedDiff.

        Args:
            diff_text: Raw output of `git diff` or similar tool.

        Returns:
            ParsedDiff with all hunks extracted.
        """
        parsed = ParsedDiff()
        current_file: str = ""
        current_hunk: Optional[DiffHunk] = None

        for raw_line in diff_text.splitlines():
            # Detect new file header: "+++ b/src/foo.py"
            file_match = cls._FILE_RE.match(raw_line)
            if file_match:
                # Flush current hunk before switching files
                if current_hunk is not None:
                    parsed.hunks.append(current_hunk)
                    current_hunk = None
                current_file = file_match.group(1)
                continue

            # Detect hunk header: "@@ -10,5 +10,8 @@ def foo():"
            hunk_match = cls._HUNK_RE.match(raw_line)
            if hunk_match:
                # Flush previous hunk
                if current_hunk is not None:
                    parsed.hunks.append(current_hunk)

                old_start = int(hunk_match.group(1))
                old_count = int(hunk_match.group(2) or 1)   # default 1 when omitted
                new_start = int(hunk_match.group(3))
                new_count = int(hunk_match.group(4) or 1)
                context = (hunk_match.group(5) or "").strip()

                current_hunk = DiffHunk(
                    file_path=current_file,
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    lines=[],
                    context=context,
                )
                continue

            # Accumulate diff lines into the current hunk
            if current_hunk is not None and raw_line and raw_line[0] in ("+", "-", " "):
                current_hunk.lines.append(raw_line)

        # Flush the last hunk
        if current_hunk is not None:
            parsed.hunks.append(current_hunk)

        logger.debug(
            "DiffParser: %d files, %d hunks", len(parsed.files), len(parsed.hunks)
        )
        return parsed


# ─────────────────────────────────────────────────────────────────────────────
# Security Scanner (pattern-based pre-scan)
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SecurityPattern:
    """
    A single regex-based security detection rule.

    Having patterns as data (not hardcoded if-chains) makes the scanner
    easy to extend: just append a new SecurityPattern to SECURITY_PATTERNS.
    """
    name: str           # short identifier, e.g. "hardcoded_secret"
    pattern: re.Pattern # compiled regex for performance
    severity: str       # "critical" | "high" | "medium" | "low"
    category: str       # "secrets" | "injection" | "auth" | "crypto" | ...
    description: str    # human-readable explanation
    cwe: str            # CWE reference, e.g. "CWE-798"
    suggestion: Optional[str] = None  # one-liner fix hint


# ── Compiled pattern library ───────────────────────────────────────────────
# Patterns are ordered from most critical to least.
# Each pattern is tested against every ADDED line ('+' prefix) in the diff.
SECURITY_PATTERNS: List[SecurityPattern] = [

    # ── Secrets & credentials ────────────────────────────────────────────────

    SecurityPattern(
        name="hardcoded_api_key",
        # Matches assignments like: api_key = "sk-abc123..." or API_KEY="..."
        pattern=re.compile(
            r'(?i)(api[_-]?key|secret[_-]?key|auth[_-]?token)\s*[=:]\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']'
        ),
        severity="critical",
        category="secrets",
        description="Hardcoded API key or secret detected — credentials committed to source control.",
        cwe="CWE-798",
        suggestion="Use os.getenv('API_KEY') and store secrets in environment variables or a vault.",
    ),

    SecurityPattern(
        name="hardcoded_password",
        pattern=re.compile(
            r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']'
        ),
        severity="critical",
        category="secrets",
        description="Hardcoded password detected in source code.",
        cwe="CWE-259",
        suggestion="Move passwords to environment variables or a secret manager (HashiCorp Vault, AWS Secrets Manager).",
    ),

    SecurityPattern(
        name="private_key_pem",
        # Matches PEM private key headers that shouldn't appear in source
        pattern=re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        severity="critical",
        category="secrets",
        description="Private key material embedded in source code.",
        cwe="CWE-321",
        suggestion="Remove immediately. Rotate the key. Store in a secrets manager.",
    ),

    SecurityPattern(
        name="aws_access_key",
        # AWS access keys are always 20-char uppercase alphanumeric starting with AKIA/ASIA
        pattern=re.compile(r"(?<![A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
        severity="critical",
        category="secrets",
        description="AWS Access Key ID found in source — rotate immediately.",
        cwe="CWE-798",
        suggestion="Rotate the key via IAM console. Use IAM roles or AWS Secrets Manager instead.",
    ),

    # ── SQL Injection ────────────────────────────────────────────────────────

    SecurityPattern(
        name="sql_injection_fstring",
        # f-strings or % formatting used to build SQL queries — classic injection vector
        pattern=re.compile(
            r'(?i)(execute|cursor\.execute|query)\s*\(\s*[f"\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP)'
        ),
        severity="high",
        category="injection",
        description="Potential SQL injection via string formatting in query construction.",
        cwe="CWE-89",
        suggestion="Use parameterised queries: cursor.execute('SELECT * FROM t WHERE id=%s', (user_id,))",
    ),

    SecurityPattern(
        name="sql_injection_format",
        pattern=re.compile(
            r'(?i)(SELECT|INSERT|UPDATE|DELETE).+%[sd]|\.format\(.+\).*(SELECT|INSERT|UPDATE|DELETE)'
        ),
        severity="high",
        category="injection",
        description="SQL query built with .format() or % — unsafe string interpolation.",
        cwe="CWE-89",
        suggestion="Replace with SQLAlchemy ORM or parameterised queries.",
    ),

    # ── Command Injection ────────────────────────────────────────────────────

    SecurityPattern(
        name="shell_injection",
        # os.system / subprocess with shell=True and a variable — injection risk
        pattern=re.compile(
            r'(os\.system|subprocess\.(call|run|Popen))\s*\(.*shell\s*=\s*True'
        ),
        severity="high",
        category="injection",
        description="shell=True with subprocess enables shell injection if input is user-controlled.",
        cwe="CWE-78",
        suggestion="Pass commands as a list and set shell=False: subprocess.run(['cmd', arg], shell=False)",
    ),

    SecurityPattern(
        name="eval_exec",
        # eval() / exec() on dynamic input is almost always a code injection vector
        pattern=re.compile(r'\b(eval|exec)\s*\((?![\"\'])[^)]+\)'),
        severity="high",
        category="injection",
        description="eval() or exec() called with a non-literal argument — potential code injection.",
        cwe="CWE-95",
        suggestion="Avoid eval/exec on user input. Use ast.literal_eval() for safe literal parsing.",
    ),

    # ── Cryptography ────────────────────────────────────────────────────────

    SecurityPattern(
        name="weak_hash_md5",
        pattern=re.compile(r'\bhashlib\.md5\b'),
        severity="medium",
        category="crypto",
        description="MD5 is cryptographically broken — do not use for security purposes.",
        cwe="CWE-327",
        suggestion="Use hashlib.sha256() for checksums, or bcrypt/argon2 for passwords.",
    ),

    SecurityPattern(
        name="weak_hash_sha1",
        pattern=re.compile(r'\bhashlib\.sha1\b'),
        severity="medium",
        category="crypto",
        description="SHA-1 is deprecated for security use — collision attacks are practical.",
        cwe="CWE-327",
        suggestion="Use hashlib.sha256() or stronger.",
    ),

    SecurityPattern(
        name="insecure_random",
        # random module is not cryptographically secure — don't use for tokens/keys
        pattern=re.compile(r'\brandom\.(random|randint|choice|shuffle|sample)\b'),
        severity="medium",
        category="crypto",
        description="random module is not cryptographically secure — unsuitable for secrets/tokens.",
        cwe="CWE-338",
        suggestion="Use secrets.token_hex() or secrets.choice() for security-sensitive randomness.",
    ),

    # ── Path Traversal ────────────────────────────────────────────────────────

    SecurityPattern(
        name="path_traversal",
        # open() called with a variable (not a literal) — could be user-controlled
        pattern=re.compile(r'open\s*\(\s*(?![\"\'])([^)]+)\)'),
        severity="medium",
        category="path_traversal",
        description="File open() with a dynamic path — verify it's not user-controlled.",
        cwe="CWE-22",
        suggestion="Validate paths with pathlib: resolved = Path(user_input).resolve(); assert resolved.is_relative_to(BASE_DIR)",
    ),

    # ── Insecure Deserialization ────────────────────────────────────────────

    SecurityPattern(
        name="pickle_load",
        pattern=re.compile(r'\bpickle\.(load|loads|Unpickler)\b'),
        severity="high",
        category="deserialization",
        description="pickle.load() on untrusted data enables arbitrary code execution.",
        cwe="CWE-502",
        suggestion="Use json.loads() for data exchange, or validate the source before unpickling.",
    ),

    SecurityPattern(
        name="yaml_unsafe_load",
        # yaml.load() without Loader= argument or with Loader=None is unsafe
        pattern=re.compile(r'\byaml\.load\s*\((?!.*Loader\s*=\s*yaml\.SafeLoader)'),
        severity="high",
        category="deserialization",
        description="yaml.load() without SafeLoader allows arbitrary Python object construction.",
        cwe="CWE-502",
        suggestion="Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
    ),

    # ── Authentication / Authorization ────────────────────────────────────

    SecurityPattern(
        name="debug_mode_enabled",
        # Django/Flask debug=True in production is a severe information disclosure risk
        pattern=re.compile(r'(?i)(DEBUG\s*=\s*True|app\.run\(.*debug\s*=\s*True)'),
        severity="high",
        category="auth",
        description="Debug mode enabled — exposes stack traces, environment vars, and interactive shell.",
        cwe="CWE-94",
        suggestion="Set DEBUG=False for production. Use environment variable: DEBUG=os.getenv('DEBUG', 'False') == 'True'",
    ),

    SecurityPattern(
        name="insecure_cors",
        # CORS wildcard in production API endpoints is an information disclosure risk
        pattern=re.compile(r'(?i)(allow_origins\s*=\s*\[?\s*["\*]|Access-Control-Allow-Origin["\s]*:\s*\*)'),
        severity="medium",
        category="auth",
        description="Wildcard CORS origin (*) allows any domain to make credentialed requests.",
        cwe="CWE-942",
        suggestion="Specify explicit allowed origins: allow_origins=['https://yourapp.com']",
    ),

    SecurityPattern(
        name="jwt_none_algorithm",
        # JWT 'none' algorithm allows signature bypass
        pattern=re.compile(r'(?i)algorithm\s*=\s*["\']none["\']'),
        severity="critical",
        category="auth",
        description="JWT 'none' algorithm disables signature verification — authentication bypass.",
        cwe="CWE-347",
        suggestion="Always specify a strong algorithm: algorithm='HS256' or 'RS256'.",
    ),

    # ── Network / HTTP ────────────────────────────────────────────────────

    SecurityPattern(
        name="ssl_verify_disabled",
        pattern=re.compile(r'verify\s*=\s*False'),
        severity="high",
        category="network",
        description="SSL certificate verification disabled — vulnerable to MITM attacks.",
        cwe="CWE-295",
        suggestion="Never set verify=False in production. Fix the certificate chain instead.",
    ),

    SecurityPattern(
        name="http_not_https",
        # Hardcoded http:// URLs in API calls (not localhost/127.0.0.1)
        pattern=re.compile(r'http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z]'),
        severity="low",
        category="network",
        description="Hardcoded HTTP URL — data transmitted in plaintext.",
        cwe="CWE-319",
        suggestion="Use HTTPS for all external URLs.",
    ),
]


class SecurityScanner:
    """
    Fast pattern-based pre-scan of a diff for common security issues.

    This runs BEFORE the LLM call and serves two purposes:
      1. Catches obvious issues instantly (no LLM latency)
      2. Provides structured context to guide the LLM's deeper analysis

    Only scans ADDED lines ('+' prefix) — we don't care about deleted code.
    """

    @classmethod
    def scan_diff(cls, parsed_diff: ParsedDiff) -> List[InlineComment]:
        """
        Scan all added lines in a ParsedDiff against SECURITY_PATTERNS.

        Returns a list of InlineComment objects ready to be posted via the
        GitHub Review API.

        Args:
            parsed_diff: Output of DiffParser.parse()

        Returns:
            List of InlineComment, one per pattern match.
        """
        comments: List[InlineComment] = []

        for hunk in parsed_diff.hunks:
            for line_no, raw_line in hunk.new_file_lines():
                # Only scan added lines — context lines and deleted lines are not new risk
                if not raw_line.startswith("+"):
                    continue

                # Strip the leading '+' for cleaner pattern matching
                code_line = raw_line[1:]

                for pattern in SECURITY_PATTERNS:
                    if pattern.pattern.search(code_line):
                        body = cls._format_comment(pattern, code_line.strip())
                        comments.append(InlineComment(
                            path=hunk.file_path,
                            line=line_no,
                            body=body,
                            severity=pattern.severity,
                            category=pattern.category,
                            side="RIGHT",
                            suggestion=pattern.suggestion,
                            diff_hunk="\n".join(hunk.lines),
                        ))
                        # One match per pattern per line — don't double-report
                        # (a line could match multiple patterns though, e.g. eval + secret)

        logger.info(
            "SecurityScanner: %d issues found in %d files",
            len(comments), len(parsed_diff.files),
        )
        return comments

    @staticmethod
    def _format_comment(pattern: SecurityPattern, matched_line: str) -> str:
        """
        Format a security finding as a Markdown comment body.

        Includes severity badge, CWE reference, description, and the matched
        code snippet for immediate context — reviewers shouldn't need to navigate
        to the file to understand the issue.
        """
        severity_emoji = {
            "critical": "🚨",
            "high": "🔴",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️",
        }.get(pattern.severity, "⚠️")

        return (
            f"{severity_emoji} **[{pattern.severity.upper()}] {pattern.name}** "
            f"— {pattern.cwe}\n\n"
            f"{pattern.description}\n\n"
            f"**Matched:** `{matched_line[:120]}`\n\n"
            f"> **Fix:** {pattern.suggestion or 'Review and remediate.'}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Helper Utilities
# ─────────────────────────────────────────────────────────────────────────────

def cache_key(data: Any) -> str:
    """Deterministic SHA-256 hex digest for any JSON-serialisable value."""
    payload = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def disk_cache(ttl_seconds: int = 3600) -> Callable[[F], F]:
    """
    Decorator factory — persist function results as JSON in CACHE_DIR.
    Uses atomic rename (tmp → final) to prevent corrupt files on crash.
    ttl_seconds=0 → never expire.
    """
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            key_data = {"func": func.__name__, "args": args, "kwargs": kwargs}
            key = cache_key(key_data)
            cache_file = CACHE_DIR / f"{key}.json"

            if cache_file.exists():
                age = time.time() - cache_file.stat().st_mtime
                if ttl_seconds == 0 or age < ttl_seconds:
                    logger.debug("Cache hit for %s (age=%.0fs)", func.__name__, age)
                    with cache_file.open("r", encoding="utf-8") as f:
                        return json.load(f)

            result = func(*args, **kwargs)
            tmp = cache_file.with_suffix(".tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(result, f, default=str, indent=2)
            tmp.replace(cache_file)  # atomic on POSIX
            return result
        return wrapper  # type: ignore[return-value]
    return decorator


def run_cmd(
    cmd: List[str],
    cwd: Optional[Path] = None,
    env_extra: Optional[Dict[str, str]] = None,
) -> Tuple[str, str, int]:
    """
    Execute a subprocess safely (no shell=True) and return (stdout, stderr, returncode).
    Never raises — callers decide how to handle non-zero exit codes.
    """
    env = {**os.environ, **(env_extra or {})}
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd or Path.cwd()),
            capture_output=True,
            text=True,
            check=False,
            env=env,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except FileNotFoundError:
        logger.warning("Command not found: %s", cmd[0])
        return "", f"Command not found: {cmd[0]}", -1
    except Exception as exc:
        logger.error("Unexpected error running %s: %s", cmd, exc)
        return "", str(exc), -1


# ─────────────────────────────────────────────────────────────────────────────
# LLM Client
# ─────────────────────────────────────────────────────────────────────────────

class MegaLLM:
    """
    Pluggable LLM client for code review, security audit, and chat.

    Works against any OpenAI-compatible /v1/chat/completions endpoint.
    Key new methods vs. the original:
      - review_inline()  → returns List[InlineComment] (not just prose)
      - security_audit() → deep AI security analysis with structured output
    """

    DEFAULT_SYSTEM_PROMPT = (
        "You are ph, a senior software engineer and security expert performing code review. "
        "Be precise, concise, and actionable. "
        "Always reference file paths and line numbers when available. "
        "Prioritise security correctness above all else. "
        "When asked for JSON output, return ONLY valid JSON — no preamble, no backticks."
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
        self.conversation_history: List[Message] = []

    def _build_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _call_api(self, messages: List[Message]) -> str:
        """
        POST to LLM endpoint with exponential back-off retry.
        System prompt is always prepended to ensure consistent behaviour.
        """
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
                resp.raise_for_status()
                data = resp.json()
                if "choices" not in data or not data["choices"]:
                    raise ValueError(f"Unexpected response shape: {list(data.keys())}")
                return data["choices"][0]["message"]["content"]

            except requests.exceptions.Timeout:
                last_exc = TimeoutError("LLM request timed out")
                logger.warning("LLM timeout (attempt %d/%d)", attempt, self.max_retries)

            except requests.exceptions.HTTPError as exc:
                last_exc = exc
                logger.warning("HTTP error from LLM (attempt %d/%d): %s", attempt, self.max_retries, exc)
                # Don't retry on non-recoverable 4xx errors (except 429)
                if exc.response and 400 <= exc.response.status_code < 500 and exc.response.status_code != 429:
                    break

            except Exception as exc:
                last_exc = exc
                logger.warning("LLM call failed (attempt %d/%d): %s", attempt, self.max_retries, exc)

            if attempt < self.max_retries:
                sleep_for = 2 ** (attempt - 1)  # 1s, 2s, 4s
                logger.info("Retrying in %ds…", sleep_for)
                time.sleep(sleep_for)

        error_msg = f"[LLM unavailable after {self.max_retries} attempts: {last_exc}]"
        logger.error(error_msg)
        return error_msg

    # ── Single-turn helpers ──────────────────────────────────────────────────

    def ask(self, prompt: str, context: Optional[str] = None) -> str:
        """Single-turn Q&A with optional codebase context grounding."""
        if context:
            full_prompt = (
                f"<codebase_context>\n{context}\n</codebase_context>\n\nQuestion: {prompt}"
            )
        else:
            full_prompt = prompt
        return self._call_api([{"role": "user", "content": full_prompt}])

    def review(self, diff: str, test_coverage: Optional[str] = None) -> str:
        """
        Prose code review of a diff.  Returns Markdown text.
        For inline comments use review_inline() instead.
        """
        coverage_block = (
            f"<test_coverage>\n{test_coverage}\n</test_coverage>"
            if test_coverage
            else "<!-- No coverage data -->"
        )
        prompt = f"""Review this diff. Output findings in this format exactly:

FINDING [SEVERITY: CRITICAL|HIGH|MEDIUM|LOW] [FILE: path] [LINE: N] [CATEGORY: bug|security|style|performance|architecture]
<one-sentence description>
SUGGESTION: <concrete fix, preferably a code snippet>
---

Focus on: bugs, security vulnerabilities, untested paths, complexity spikes, architectural issues.

{coverage_block}

<diff>
{diff}
</diff>"""
        return self._call_api([{"role": "user", "content": prompt}])

    def review_inline(
        self,
        parsed_diff: ParsedDiff,
        existing_security_comments: Optional[List[InlineComment]] = None,
    ) -> List[InlineComment]:
        """
        Deep AI review that produces structured InlineComment objects.

        Strategy:
          - Review each file's hunks individually (avoids token limits)
          - Ask the LLM to output JSON conforming to a defined schema
          - Merge with pattern-based security findings (deduplicated by line)
          - Return a flat list ready for the GitHub Review API

        Args:
            parsed_diff:                 Output of DiffParser.parse()
            existing_security_comments:  Pattern-based comments to merge with AI findings.

        Returns:
            List[InlineComment] — all findings, deduplicated by (path, line, category).
        """
        all_comments: List[InlineComment] = list(existing_security_comments or [])

        # Process file by file to stay within context window limits
        for file_path in parsed_diff.files:
            file_hunks = parsed_diff.hunks_for_file(file_path)
            if not file_hunks:
                continue

            # Build a compact diff excerpt for this file only
            diff_excerpt = f"File: {file_path}\n"
            for hunk in file_hunks:
                diff_excerpt += (
                    f"\n@@ -{hunk.old_start},{hunk.old_count} "
                    f"+{hunk.new_start},{hunk.new_count} @@ {hunk.context}\n"
                )
                diff_excerpt += "\n".join(hunk.lines)

            # Structured prompt — ask for JSON so we can parse it reliably
            prompt = f"""Analyse this diff excerpt and return ONLY a JSON array of findings.
Each finding must conform to this schema:
{{
  "line": <int, line number in the new file>,
  "severity": "critical|high|medium|low|info",
  "category": "bug|security|style|performance|architecture|test",
  "description": "<one sentence>",
  "suggestion": "<concrete code fix or null>"
}}

Rules:
- Only report lines that appear in this diff (new_start to new_start+new_count).
- Do not report false positives — be conservative.
- If no issues found, return [].
- Return ONLY the JSON array, nothing else.

<diff_excerpt>
{diff_excerpt}
</diff_excerpt>"""

            raw_response = self._call_api([{"role": "user", "content": prompt}])

            # Parse the JSON response — strip stray backticks defensively
            clean = raw_response.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            try:
                findings = json.loads(clean)
                if not isinstance(findings, list):
                    raise ValueError("Expected a JSON array")
            except (json.JSONDecodeError, ValueError) as exc:
                logger.warning(
                    "LLM returned non-JSON for %s: %s | raw=%r", file_path, exc, raw_response[:200]
                )
                continue  # Skip this file; don't crash the whole review

            for f in findings:
                # Validate line number is in the expected range for this file
                line_no = int(f.get("line", 0))
                if line_no <= 0:
                    continue

                body = (
                    f"**[{f.get('severity', 'medium').upper()}]** "
                    f"_{f.get('category', 'bug')}_ — {f.get('description', '')}"
                )

                all_comments.append(InlineComment(
                    path=file_path,
                    line=line_no,
                    body=body,
                    severity=f.get("severity", "medium"),
                    category=f.get("category", "bug"),
                    side="RIGHT",
                    suggestion=f.get("suggestion"),
                ))

        # Deduplicate: keep the most severe finding per (path, line, category) triple
        deduped = self._deduplicate_comments(all_comments)
        logger.info(
            "review_inline: %d raw findings → %d after dedup", len(all_comments), len(deduped)
        )
        return deduped

    def security_audit(self, diff: str, repo_context: Optional[str] = None) -> str:
        """
        Deep security-focused analysis of a diff.

        Returns a structured Markdown security report covering:
          - OWASP Top 10 violations
          - Authentication/authorization flaws
          - Cryptographic weaknesses
          - Data validation gaps
          - Secrets and credential exposure
        """
        context_block = (
            f"<repo_context>\n{repo_context}\n</repo_context>\n"
            if repo_context
            else ""
        )

        prompt = f"""You are a security engineer conducting a thorough security audit.

{context_block}

Analyse the following diff for security vulnerabilities. For each finding:
1. Reference the exact file and line number
2. Explain the attack vector (how an attacker would exploit it)
3. Rate CVSS severity (Critical/High/Medium/Low)
4. Map to OWASP Top 10 2021 category and CWE ID
5. Provide a specific, copy-pasteable code fix

Check for (but don't limit to):
- Injection attacks (SQL, Command, LDAP, XSS, XXE)
- Broken authentication and session management
- Sensitive data exposure (credentials, PII, tokens)
- Insecure cryptography (weak algorithms, hardcoded keys)
- Path traversal and directory listing
- Insecure deserialization (pickle, yaml.load, eval)
- Missing input validation and output encoding
- SSRF and open redirect vulnerabilities
- Race conditions and TOCTOU issues
- Information leakage via error messages or logs

<diff>
{diff}
</diff>

Output a Markdown security report. Be precise — only report real issues."""

        return self._call_api([{"role": "user", "content": prompt}])

    def brief(self, repo_info: RepoInfo) -> str:
        """Generate an ONBOARDING.md for new contributors."""
        repo_yaml = yaml.dump(repo_info, default_flow_style=False, sort_keys=True)
        prompt = f"""Generate a complete ONBOARDING.md.

Sections required:
1. Project Overview (2–3 sentences)
2. Architecture Summary
3. Getting Started (setup commands)
4. Key Entry Points
5. Ownership Map
6. Health Status (score + top issues)

<repo_analysis>
{repo_yaml}
</repo_analysis>"""
        return self._call_api([{"role": "user", "content": prompt}])

    def chat(self, user_input: str) -> str:
        """Persistent multi-turn chat."""
        self.conversation_history.append({"role": "user", "content": user_input})
        response = self._call_api(self.conversation_history)
        self.conversation_history.append({"role": "assistant", "content": response})
        return response

    def reset_chat(self) -> None:
        self.conversation_history.clear()

    def generate_fix(self, finding: Finding, code_snippet: str) -> str:
        """Generate a unified diff patch for a specific finding."""
        prompt = f"""Output ONLY a unified diff patch. No explanations, no backticks.

Finding:
  Description : {finding.get("description", "N/A")}
  Severity    : {finding.get("severity", "medium")}
  File        : {finding.get("file", "unknown")}
  Line        : {finding.get("line", "N/A")}

Original code:
{code_snippet}"""
        return self._call_api([{"role": "user", "content": prompt}])

    def summarise_findings(self, findings: List[Finding]) -> str:
        """Executive summary of findings for non-technical stakeholders."""
        if not findings:
            return "No findings to summarise."
        findings_yaml = yaml.dump(findings, default_flow_style=False)
        prompt = (
            "Summarise these findings in 3–5 bullet points for a non-technical manager. "
            f"Group by severity.\n\n{findings_yaml}"
        )
        return self._call_api([{"role": "user", "content": prompt}])

    # ── Internal ─────────────────────────────────────────────────────────────

    @staticmethod
    def _deduplicate_comments(comments: List[InlineComment]) -> List[InlineComment]:
        """
        Remove duplicate findings at the same (path, line, category).
        When duplicates exist, keep the one with higher severity.
        """
        severity_rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        best: Dict[Tuple[str, int, str], InlineComment] = {}

        for c in comments:
            key = (c.path, c.line, c.category)
            existing = best.get(key)
            if existing is None:
                best[key] = c
            else:
                # Replace if this comment has higher severity
                if severity_rank.get(c.severity, 0) > severity_rank.get(existing.severity, 0):
                    best[key] = c

        return list(best.values())

    # ── New agents — Code Quality & Performance ───────────────────────────────

    def analyze_code_quality(self, parsed_diff: "ParsedDiff") -> List[InlineComment]:
        """
        Code Quality Agent — detects bad naming, poor readability, duplicated
        logic, large functions, and bad practices.

        Input/output contract is identical to review_inline():
          - Takes a ParsedDiff (from DiffParser.parse())
          - Returns List[InlineComment] ready for GitHubClient.post_pr_review()
          - Returns [] on any failure (never raises — pipeline must stay alive)

        Called from process_pr() in main.py after review_inline().
        Results are merged with existing inline_comments before posting.
        """
        results: List[InlineComment] = []

        for file_path in parsed_diff.files:
            file_hunks = parsed_diff.hunks_for_file(file_path)
            if not file_hunks:
                continue

            # Build the per-file diff excerpt (same pattern as review_inline)
            diff_excerpt = f"File: {file_path}\n"
            for hunk in file_hunks:
                diff_excerpt += (
                    f"\n@@ -{hunk.old_start},{hunk.old_count} "
                    f"+{hunk.new_start},{hunk.new_count} @@ {hunk.context}\n"
                )
                diff_excerpt += "\n".join(hunk.lines)

            # Build the line number catalog so the LLM anchors to real lines
            valid_lines = [ln for h in file_hunks for ln, _ in h.new_file_lines()]

            prompt = f"""You are a code quality reviewer. Analyse this diff for code quality issues ONLY.
Do NOT report security vulnerabilities — those are handled by a separate agent.

Detect:
- Bad or unclear variable/function names (single letters, abbreviations like tmp, q, t)
- Poor readability (deeply nested code, long functions > 50 lines)
- Duplicated logic (same loop or block repeated)
- Bad practices (mutable default args, bare except, print() in library code)
- Dead code (unreachable lines after return, unused variables)

Return ONLY a JSON array. Each item must use exactly these keys:
{{
  "line": <int — must be one of {valid_lines[:50]}>,
  "severity": "high|medium|low",
  "category": "quality",
  "description": "<one sentence>",
  "suggestion": "<concrete fix or null>"
}}

Rules:
- Only report lines present in this diff.
- Be conservative — skip low-confidence findings.
- If no issues, return [].
- Return ONLY the JSON array, no extra text.

<diff_excerpt>
{diff_excerpt}
</diff_excerpt>"""

            try:
                raw_response = self._call_api([{"role": "user", "content": prompt}])

                # Robust JSON extraction — strip accidental markdown fences
                clean = re.sub(r'^```(?:json)?\s*', '', raw_response.strip())
                clean = re.sub(r'\s*```$', '', clean).strip()

                findings = json.loads(clean)
                if not isinstance(findings, list):
                    continue

                for f in findings:
                    try:
                        line_no = int(f.get("line", 0))
                    except (TypeError, ValueError):
                        continue
                    if line_no <= 0:
                        continue

                    body = (
                        f"**[{f.get('severity', 'medium').upper()}]** "
                        f"_quality_ — {f.get('description', '')}"
                    )
                    results.append(InlineComment(
                        path=file_path,
                        line=line_no,
                        body=body,
                        severity=f.get("severity", "medium"),
                        category="quality",
                        side="RIGHT",
                        suggestion=f.get("suggestion"),
                    ))

            except Exception as exc:
                logger.warning(
                    "Code quality agent failed for %s: %s", file_path, exc
                )
                continue  # one file failing must not kill the rest

        logger.info(
            "analyze_code_quality: %d findings across %d files",
            len(results), len(parsed_diff.files),
        )
        return results

    def analyze_performance(self, parsed_diff: "ParsedDiff") -> List[InlineComment]:
        """
        Performance Agent — detects unnecessary loops, inefficient queries,
        blocking operations, redundant computations, and memory inefficiency.

        Input/output contract is identical to review_inline():
          - Takes a ParsedDiff (from DiffParser.parse())
          - Returns List[InlineComment] ready for GitHubClient.post_pr_review()
          - Returns [] on any failure (never raises — pipeline must stay alive)

        Called from process_pr() in main.py after review_inline().
        Results are merged with existing inline_comments before posting.
        """
        results: List[InlineComment] = []

        for file_path in parsed_diff.files:
            file_hunks = parsed_diff.hunks_for_file(file_path)
            if not file_hunks:
                continue

            # Build the per-file diff excerpt
            diff_excerpt = f"File: {file_path}\n"
            for hunk in file_hunks:
                diff_excerpt += (
                    f"\n@@ -{hunk.old_start},{hunk.old_count} "
                    f"+{hunk.new_start},{hunk.new_count} @@ {hunk.context}\n"
                )
                diff_excerpt += "\n".join(hunk.lines)

            valid_lines = [ln for h in file_hunks for ln, _ in h.new_file_lines()]

            prompt = f"""You are a performance engineering reviewer. Analyse this diff for performance issues ONLY.
Do NOT report security or style/naming issues — those are handled by separate agents.

Detect:
- Unnecessary loops or O(n²) complexity where O(n) is achievable
- Repeated list lookups that should use a set or dict for O(1) access
- Redundant computations inside loops (precompute outside)
- Blocking I/O / synchronous DB calls in hot code paths
- Memory-inefficient patterns (building large lists that could be generators)
- String concatenation inside loops (use str.join())
- Sorting inside loops (sort once outside)

Return ONLY a JSON array. Each item must use exactly these keys:
{{
  "line": <int — must be one of {valid_lines[:50]}>,
  "severity": "high|medium|low",
  "category": "performance",
  "description": "<one sentence>",
  "suggestion": "<concrete fix or null>"
}}

Rules:
- Only report lines present in this diff.
- Be conservative — skip low-confidence findings.
- If no issues, return [].
- Return ONLY the JSON array, no extra text.

<diff_excerpt>
{diff_excerpt}
</diff_excerpt>"""

            try:
                raw_response = self._call_api([{"role": "user", "content": prompt}])

                # Robust JSON extraction
                clean = re.sub(r'^```(?:json)?\s*', '', raw_response.strip())
                clean = re.sub(r'\s*```$', '', clean).strip()

                findings = json.loads(clean)
                if not isinstance(findings, list):
                    continue

                for f in findings:
                    try:
                        line_no = int(f.get("line", 0))
                    except (TypeError, ValueError):
                        continue
                    if line_no <= 0:
                        continue

                    body = (
                        f"**[{f.get('severity', 'medium').upper()}]** "
                        f"_performance_ — {f.get('description', '')}"
                    )
                    results.append(InlineComment(
                        path=file_path,
                        line=line_no,
                        body=body,
                        severity=f.get("severity", "medium"),
                        category="performance",
                        side="RIGHT",
                        suggestion=f.get("suggestion"),
                    ))

            except Exception as exc:
                logger.warning(
                    "Performance agent failed for %s: %s", file_path, exc
                )
                continue

        logger.info(
            "analyze_performance: %d findings across %d files",
            len(results), len(parsed_diff.files),
        )
        return results


# ─────────────────────────────────────────────────────────────────────────────
# Score Utilities
# ─────────────────────────────────────────────────────────────────────────────

def score_band(score: float) -> str:
    for label, lo, hi in SCORE_BANDS:
        if lo <= score <= hi:
            return label
    return "UNKNOWN"


def print_health_report(report: HealthReport) -> None:
    bar_width = 40
    filled = int(report.final_score / 100 * bar_width)
    bar = "█" * filled + "░" * (bar_width - filled)
    print(f"\n{'─' * 60}")
    print(f"  Health Score: {report.final_score:.1f}/100  [{report.band}]")
    print(f"  [{bar}]")
    print(f"{'─' * 60}")
    for mid, result in sorted(report.module_results.items()):
        icon = "✅" if result.score >= 75 else "⚠️ " if result.score >= 50 else "❌"
        print(f"  {icon}  {mid}  {result.score:6.1f}  ({len(result.findings)} findings)")
    print(f"{'─' * 60}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ph", description="Codebase Health Score & AI Review")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    ask_p = sub.add_parser("ask", help="One-shot question about the codebase")
    ask_p.add_argument("question", nargs="+")
    ask_p.add_argument("--context-file", metavar="FILE")

    rev_p = sub.add_parser("review", help="AI code review (prose output)")
    rev_p.add_argument("diff_file", metavar="DIFF")
    rev_p.add_argument("--coverage", metavar="FILE")
    rev_p.add_argument("--inline", action="store_true", help="Output inline comments as JSON")

    sec_p = sub.add_parser("security", help="Security-focused audit of a diff")
    sec_p.add_argument("diff_file", metavar="DIFF")
    sec_p.add_argument("--context-file", metavar="FILE", help="Optional repo context")

    sub.add_parser("brief", help="Generate ONBOARDING.md")

    fix_p = sub.add_parser("fix", help="Generate a patch for a finding")
    fix_p.add_argument("finding_json", metavar="JSON")
    fix_p.add_argument("snippet_file", metavar="FILE")

    sub.add_parser("chat", help="Interactive multi-turn chat")

    return parser


def main() -> int:
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
            diff_text = Path(args.diff_file).read_text(encoding="utf-8")

            if args.inline:
                # Parse diff → run security scan → run AI review → output JSON
                parsed = DiffParser.parse(diff_text)
                sec_comments = SecurityScanner.scan_diff(parsed)
                inline_comments = llm.review_inline(parsed, existing_security_comments=sec_comments)
                # Output as JSON for the webhook to pick up and post to GitHub
                print(json.dumps([c.to_dict() for c in inline_comments], indent=2))
            else:
                coverage: Optional[str] = None
                if args.coverage:
                    coverage = Path(args.coverage).read_text(encoding="utf-8")
                print(llm.review(diff_text, test_coverage=coverage))

        elif args.command == "security":
            diff_text = Path(args.diff_file).read_text(encoding="utf-8")
            repo_ctx: Optional[str] = None
            if args.context_file:
                repo_ctx = Path(args.context_file).read_text(encoding="utf-8")
            # Run pattern scanner first for instant feedback
            parsed = DiffParser.parse(diff_text)
            pattern_hits = SecurityScanner.scan_diff(parsed)
            if pattern_hits:
                print(f"## Pattern-based findings ({len(pattern_hits)} hits)\n")
                for c in pattern_hits:
                    print(f"- [{c.severity.upper()}] {c.path}:{c.line} — {c.body[:80]}…\n")
            # Then deep LLM audit
            print("\n## AI Security Audit\n")
            print(llm.security_audit(diff_text, repo_context=repo_ctx))

        elif args.command == "brief":
            repo_info: RepoInfo = {
                "architecture": "Monorepo",
                "entry_points": ["ai_agent.py", "main.py"],
                "owners": {},
                "tech_stack": ["Python 3.11", "FastAPI", "httpx"],
                "health_score": "N/A — run full scan first",
            }
            print(llm.brief(repo_info))

        elif args.command == "fix":
            finding = json.loads(args.finding_json)
            snippet = Path(args.snippet_file).read_text(encoding="utf-8")
            print(llm.generate_fix(finding, snippet))

        else:
            # Default: interactive chat
            print("ph AI — type 'exit' or Ctrl-C to quit. '/reset' to clear history.\n")
            while True:
                try:
                    user_input = input("You: ").strip()
                except (KeyboardInterrupt, EOFError):
                    print("\nBye!")
                    break
                if not user_input:
                    continue
                if user_input.lower() in {"exit", "quit", "bye"}:
                    break
                if user_input == "/reset":
                    llm.reset_chat()
                    print("[History cleared]\n")
                    continue
                print(f"\nph: {llm.chat(user_input)}\n")

    except FileNotFoundError as exc:
        logger.error("File not found: %s", exc)
        return 1
    except json.JSONDecodeError as exc:
        logger.error("Invalid JSON: %s", exc)
        return 1
    except Exception as exc:
        logger.error("Unhandled error:\n%s", traceback.format_exc())
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())