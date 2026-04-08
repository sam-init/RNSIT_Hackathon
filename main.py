"""
webhook.py — GitHub Webhook Receiver for ph AI Code Review
===========================================================

Receives GitHub PR webhook events, verifies HMAC-SHA256 signatures,
and dispatches background AI review jobs.

Environment variables (set in your deployment secrets):
    GITHUB_TOKEN    — Fine-grained PAT with `pull_requests: write` permission
    WEBHOOK_SECRET  — Must match the secret configured in GitHub → Settings → Webhooks

Run locally:
    uvicorn webhook:app --reload --port 8000

Production (e.g., Render):
    uvicorn webhook:app --host 0.0.0.0 --port $PORT --workers 2
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx                          # async-native HTTP — replaces requests for async contexts
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)-8s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,  # Stdout for container log aggregators (Cloud Run, Render, etc.)
)
logger = logging.getLogger("ph.webhook")

# ─────────────────────────────────────────────────────────────────────────────
# Configuration — read from environment, fail loudly if required values missing
# ─────────────────────────────────────────────────────────────────────────────

def _require_env(name: str) -> str:
    """
    Read an environment variable and raise a clear error if it is absent.
    Avoids the silent None-propagation bug in the original code where
    os.getenv("/etc/secrets/GITHUB_TOKEN") always returns None because the
    argument should be the variable NAME, not the secrets file path.
    """
    value = os.environ.get(name)
    if not value:
        # Raise at import time so the server refuses to start rather than
        # silently accepting requests with a broken configuration
        raise RuntimeError(
            f"Required environment variable '{name}' is not set. "
            "Set it in your deployment secrets or .env file."
        )
    return value


# NOTE: Original code used os.getenv("/etc/secrets/GITHUB_TOKEN") — that path
# string was passed as the variable *name*, not as a file path, so it always
# returned None.  Correct approach: set the env var directly in your platform
# (Render secret env, Docker --env-file, etc.) and read it by name.
GITHUB_TOKEN: str = _require_env("GITHUB_TOKEN")
WEBHOOK_SECRET: bytes = _require_env("WEBHOOK_SECRET").encode("utf-8")

# GitHub API base URL — externalised so tests can point at a mock server
GITHUB_API_BASE: str = os.getenv("GITHUB_API_BASE", "https://api.github.com")

# Maximum threads for background PR processing
# (ThreadPoolExecutor is sufficient here; switch to a task queue like Celery
#  or ARQ if processing becomes CPU-heavy or needs retry persistence)
MAX_BACKGROUND_WORKERS: int = int(os.getenv("PH_WEBHOOK_WORKERS", "4"))

# ─────────────────────────────────────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────────────────────────────────────

@dataclass(frozen=True)           # frozen=True makes it immutable and hashable
class PRContext:
    """
    Lightweight value object capturing the essential facts about a PR event.
    Extracting this from the raw payload early means process_pr() doesn't need
    to navigate nested dicts everywhere — reduces KeyError risk considerably.
    """
    repo: str                     # "owner/repo"
    pr_number: int
    pr_title: str
    pr_url: str
    author: str
    base_branch: str
    head_branch: str
    diff_url: str

    @classmethod
    def from_payload(cls, payload: Dict[str, Any]) -> "PRContext":
        """
        Extract a PRContext from a raw GitHub webhook payload dict.
        Raises KeyError with a descriptive message if the payload is malformed.
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
                diff_url=pr["diff_url"],
            )
        except KeyError as exc:
            raise ValueError(f"Malformed PR payload — missing key: {exc}") from exc


# ─────────────────────────────────────────────────────────────────────────────
# Security — HMAC Signature Verification
# ─────────────────────────────────────────────────────────────────────────────

def verify_github_signature(payload_body: bytes, signature_header: Optional[str]) -> None:
    """
    Verify the X-Hub-Signature-256 header sent by GitHub.

    GitHub signs each webhook payload with HMAC-SHA256 using the shared secret.
    We recompute the MAC over the raw request bytes and compare with
    hmac.compare_digest (constant-time comparison to prevent timing attacks).

    Args:
        payload_body:      Raw request body bytes (must be read BEFORE parsing JSON).
        signature_header:  Value of the X-Hub-Signature-256 request header.

    Raises:
        HTTPException(403): If the header is missing, malformed, or the MAC doesn't match.

    Security notes:
    - We read the raw body before JSON parsing to verify the exact bytes GitHub signed.
    - compare_digest prevents timing side-channel attacks that a naive == would expose.
    - Both strings are lowercased before comparison to handle case differences safely.
    """
    if not signature_header:
        logger.warning("Rejected request: missing X-Hub-Signature-256 header")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Missing X-Hub-Signature-256 header",
        )

    # Expected format: "sha256=<hex_digest>"
    parts = signature_header.split("=", maxsplit=1)
    if len(parts) != 2 or parts[0] != "sha256":
        logger.warning("Rejected request: malformed signature header: %s", signature_header)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Malformed signature header — expected 'sha256=<hex>'",
        )

    received_digest = parts[1]

    # Compute expected MAC using our shared secret
    expected_mac = hmac.new(WEBHOOK_SECRET, msg=payload_body, digestmod=hashlib.sha256)
    expected_digest = expected_mac.hexdigest()

    # Constant-time comparison — both sides must be the same type (str)
    if not hmac.compare_digest(expected_digest, received_digest.lower()):
        logger.warning("Rejected request: signature mismatch")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Signature verification failed",
        )

    logger.debug("Signature verified ✓")


# ─────────────────────────────────────────────────────────────────────────────
# GitHub API Client
# ─────────────────────────────────────────────────────────────────────────────

class GitHubClient:
    """
    Thin wrapper around the GitHub REST API.

    Uses httpx.Client (synchronous) because process_pr runs in a thread pool,
    not in the async event loop.  If you later migrate to async workers, swap
    to httpx.AsyncClient.

    A single session is reused across calls to benefit from keep-alive
    connection pooling — avoids the overhead of a new TCP handshake per request.
    """

    def __init__(self, token: str, base_url: str = GITHUB_API_BASE) -> None:
        self._base = base_url.rstrip("/")
        # Build a persistent session with auth headers set once
        self._client = httpx.Client(
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                # GitHub requires a user-agent; identify our app specifically
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "ph-webhook/1.0",
            },
            timeout=15.0,  # seconds — fail fast rather than hanging
        )

    def post_comment(self, repo: str, issue_number: int, body: str) -> Dict[str, Any]:
        """
        Post a comment on a PR (issues and PRs share the same comments endpoint).

        Args:
            repo:         "owner/repo"
            issue_number: PR number
            body:         Markdown-formatted comment text

        Returns:
            The created comment object from the GitHub API.

        Raises:
            httpx.HTTPStatusError: If the API returns a 4xx/5xx response.
        """
        url = f"{self._base}/repos/{repo}/issues/{issue_number}/comments"
        response = self._client.post(url, json={"body": body})

        # raise_for_status() converts 4xx/5xx into exceptions with response details
        response.raise_for_status()

        logger.info(
            "Comment posted on %s#%d (comment_id=%s)",
            repo, issue_number, response.json().get("id")
        )
        return response.json()

    def get_diff(self, diff_url: str) -> str:
        """
        Fetch the raw unified diff for a PR.

        GitHub serves the diff when the Accept header is set to
        application/vnd.github.diff — override the default JSON accept header.
        """
        response = self._client.get(
            diff_url,
            headers={"Accept": "application/vnd.github.diff"},
        )
        response.raise_for_status()
        return response.text

    def close(self) -> None:
        """Release the underlying connection pool. Call when the process shuts down."""
        self._client.close()


# ─────────────────────────────────────────────────────────────────────────────
# Background PR Processor
# ─────────────────────────────────────────────────────────────────────────────

def process_pr(ctx: PRContext, github: GitHubClient) -> None:
    """
    Handle a newly opened PR: post an acknowledgement comment, fetch the diff,
    run AI review (stubbed here — wire in MegaLLM.review), and post findings.

    This runs in a ThreadPoolExecutor worker thread — never call async code
    directly from here.  Any exception is caught and logged so the thread pool
    doesn't silently swallow errors.

    Args:
        ctx:    Immutable PR context extracted from the webhook payload.
        github: Shared GitHubClient instance (thread-safe for reads; the
                underlying httpx.Client uses connection-level locking).
    """
    logger.info("▶ Processing PR %s#%d ('%s')", ctx.repo, ctx.pr_number, ctx.pr_title)

    try:
        # ── Step 1: Acknowledge the PR immediately so authors know review started ──
        ack_comment = (
            f"🔍 **ph AI Review started** for PR #{ctx.pr_number} by @{ctx.author}.\n"
            f"> Branch: `{ctx.head_branch}` → `{ctx.base_branch}`\n\n"
            "_Review findings will be posted as inline comments shortly._"
        )
        github.post_comment(ctx.repo, ctx.pr_number, ack_comment)

        # ── Step 2: Fetch the diff ─────────────────────────────────────────────
        logger.info("Fetching diff from %s", ctx.diff_url)
        diff = github.get_diff(ctx.diff_url)

        if not diff.strip():
            logger.info("Empty diff — nothing to review for PR %s#%d", ctx.repo, ctx.pr_number)
            github.post_comment(
                ctx.repo, ctx.pr_number,
                "ℹ️ **ph**: Diff is empty — no review needed."
            )
            return

        # ── Step 3: AI Review ─────────────────────────────────────────────────
        # Stubbed — wire in: from ph import MegaLLM; llm = MegaLLM(); review = llm.review(diff)
        # For now we return a placeholder so the webhook is usable end-to-end.
        review_result = (
            "⚠️ AI review engine not connected yet. "
            "Wire `MegaLLM.review()` into `process_pr()` to enable findings."
        )

        # ── Step 4: Post review results ────────────────────────────────────────
        findings_comment = (
            f"## 🤖 ph AI Review — PR #{ctx.pr_number}\n\n"
            f"{review_result}\n\n"
            "---\n_Powered by [ph](https://github.com/your-org/ph)_"
        )
        github.post_comment(ctx.repo, ctx.pr_number, findings_comment)
        logger.info("✅ Review complete for PR %s#%d", ctx.repo, ctx.pr_number)

    except httpx.HTTPStatusError as exc:
        # GitHub API rejected our request — log details, don't crash the worker
        logger.error(
            "GitHub API error on PR %s#%d: HTTP %d — %s",
            ctx.repo, ctx.pr_number, exc.response.status_code, exc.response.text,
        )
    except Exception:  # noqa: BLE001
        # Catch-all so one bad PR doesn't kill the worker thread
        logger.error(
            "Unhandled error processing PR %s#%d:\n%s",
            ctx.repo, ctx.pr_number, traceback.format_exc(),
        )


# ─────────────────────────────────────────────────────────────────────────────
# Application Lifecycle
# ─────────────────────────────────────────────────────────────────────────────

# Shared resources initialised once at startup and cleaned up on shutdown.
# Using module-level variables avoids the overhead of creating a new client
# per request, and ensures the connection pool is properly closed.
_executor: Optional[ThreadPoolExecutor] = None
_github_client: Optional[GitHubClient] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager (replaces deprecated on_event handlers).
    Initialises shared resources on startup and tears them down on shutdown.
    """
    global _executor, _github_client

    logger.info("🚀 Starting ph webhook server…")
    _executor = ThreadPoolExecutor(max_workers=MAX_BACKGROUND_WORKERS, thread_name_prefix="pr-worker")
    _github_client = GitHubClient(token=GITHUB_TOKEN)
    logger.info("Worker pool: %d threads | GitHub API: %s", MAX_BACKGROUND_WORKERS, GITHUB_API_BASE)

    yield  # Server is running between yield and the lines below

    logger.info("🛑 Shutting down — waiting for in-flight PR jobs…")
    if _executor:
        _executor.shutdown(wait=True)   # Drain the queue gracefully before exit
    if _github_client:
        _github_client.close()
    logger.info("Shutdown complete.")


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI Application
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="ph Webhook",
    description="GitHub webhook receiver for AI-powered code review",
    version="1.0.0",
    lifespan=lifespan,   # Wire in the startup/shutdown lifecycle
    # Disable /docs in production to reduce attack surface
    # docs_url=None, redoc_url=None,
)


@app.get("/health", tags=["ops"])
async def health_check() -> Dict[str, str]:
    """
    Liveness probe endpoint.
    Render, Railway, and Kubernetes call this to determine if the pod is healthy.
    Returns HTTP 200 with a minimal JSON body — no secrets, no internals.
    """
    return {"status": "ok", "service": "ph-webhook"}


@app.post("/webhook", tags=["webhook"])
async def webhook(
    request: Request,
    x_hub_signature_256: Optional[str] = Header(default=None),  # FastAPI auto-parses headers
    x_github_event: Optional[str] = Header(default=None),       # "pull_request", "push", etc.
    x_github_delivery: Optional[str] = Header(default=None),    # Unique delivery UUID for deduplication
) -> JSONResponse:
    """
    Receive and dispatch GitHub webhook events.

    Flow:
      1. Read raw body bytes (must happen before JSON parsing — we need bytes for HMAC)
      2. Verify HMAC-SHA256 signature
      3. Parse JSON payload
      4. Route by event type and action
      5. Dispatch background job for PR open events

    The endpoint returns 200 immediately after dispatching the background job.
    GitHub marks a delivery as failed if it doesn't receive a response within 10s,
    so we never block on the AI review inside the request handler.
    """
    logger.info(
        "Webhook received | event=%s | delivery=%s",
        x_github_event or "unknown",
        x_github_delivery or "unknown",
    )

    # ── Step 1: Read raw bytes — MUST happen before request.json() ───────────
    # FastAPI's Request caches the body, but we explicitly read bytes first to
    # ensure we're verifying exactly what was sent over the wire.
    raw_body = await request.body()

    # ── Step 2: Verify signature ──────────────────────────────────────────────
    verify_github_signature(raw_body, x_hub_signature_256)

    # ── Step 3: Parse payload ─────────────────────────────────────────────────
    try:
        payload: Dict[str, Any] = await request.json()
    except Exception as exc:
        logger.warning("Failed to parse webhook JSON: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Request body is not valid JSON",
        ) from exc

    action: str = payload.get("action", "")
    logger.info("Event: %s / action: %s", x_github_event, action)

    # ── Step 4: Route by event + action ───────────────────────────────────────
    if x_github_event == "pull_request" and action == "opened":
        try:
            ctx = PRContext.from_payload(payload)
        except ValueError as exc:
            logger.error("Malformed PR payload: %s", exc)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc

        # ── Step 5: Dispatch non-blocking background job ──────────────────────
        # ThreadPoolExecutor.submit() returns a Future immediately; we don't
        # await it here so the webhook handler returns to GitHub within milliseconds.
        if _executor and _github_client:
            _executor.submit(process_pr, ctx, _github_client)
            logger.info("PR %s#%d queued for review", ctx.repo, ctx.pr_number)
        else:
            # Should never happen if lifespan ran correctly
            logger.error("Executor or GitHub client not initialised — dropping event")

    elif x_github_event == "ping":
        # GitHub sends a ping when you first configure a webhook — acknowledge it
        logger.info("GitHub ping received (zen: %s)", payload.get("zen", "—"))

    else:
        # All other events (push, issues, etc.) are intentionally ignored for now
        logger.debug("Ignoring event: %s/%s", x_github_event, action)

    # Always return 200 to prevent GitHub from retrying
    return JSONResponse(content={"status": "ok"}, status_code=status.HTTP_200_OK)


# ─────────────────────────────────────────────────────────────────────────────
# Dev server entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    # Use reload=True only for local development; never in production
    uvicorn.run(
        "webhook:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=True,    # Auto-reload on file changes
        log_level="info",
    )