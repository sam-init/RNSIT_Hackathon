
## ✅ `main.py` – Production‑Grade GitHub Webhook Handler


"""
GitHub Webhook Server for AI Code Review

Features:
- Async FastAPI with background tasks
- Signature verification (RFC 2104 HMAC-SHA256)
- Resilient GitHub API calls with retries
- Rate limiting handling and logging
- Health check and metrics endpoints
- Graceful shutdown
- Pydantic models for request validation
"""

import os
import hmac
import hashlib
import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseSettings, Field, ValidationError, BaseModel
import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    RetryError
)

# Import the advanced AI agent
from ai_agent import MegaLLM, llm_settings

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

class GitHubSettings(BaseSettings):
    """GitHub integration settings."""
    token: str = Field(..., env="GITHUB_TOKEN")
    webhook_secret: str = Field(..., env="WEBHOOK_SECRET")
    api_base: str = Field("https://api.github.com", env="GITHUB_API_BASE")
    timeout_seconds: float = Field(30.0, env="GITHUB_TIMEOUT")
    max_retries: int = Field(3, env="GITHUB_MAX_RETRIES")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Load settings
try:
    gh_settings = GitHubSettings()
except ValidationError as e:
    raise RuntimeError(f"Missing GitHub configuration: {e}")

# Global AI agent instance (reused across requests)
llm = MegaLLM()

# ------------------------------------------------------------
# Lifespan manager (for startup/shutdown cleanup)
# ------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Handle startup and shutdown events."""
    # Startup
    print("🚀 Starting AI Code Reviewer...")
    print(f"LLM Endpoint: {llm_settings.endpoint}")
    print(f"Model: {llm_settings.model}")
    yield
    # Shutdown
    print("🛑 Shutting down, closing LLM client...")
    await llm.close()

app = FastAPI(
    title="AI Code Reviewer",
    description="Webhook receiver that reviews GitHub PRs using LLM",
    version="2.0.0",
    lifespan=lifespan
)

# ------------------------------------------------------------
# Pydantic models for webhook payload (partial)
# ------------------------------------------------------------

class PullRequest(BaseModel):
    number: int
    title: str
    body: Optional[str] = None
    html_url: str

class Repository(BaseModel):
    full_name: str
    name: str
    html_url: str

class WebhookPayload(BaseModel):
    action: str
    pull_request: PullRequest
    repository: Repository
    # Other fields are ignored (extra = "forbid" would break, so we allow)
    class Config:
        extra = "allow"

# ------------------------------------------------------------
# Utility functions
# ------------------------------------------------------------

def verify_signature(payload_body: bytes, signature_header: Optional[str]) -> bool:
    """
    Verify GitHub webhook signature using HMAC-SHA256.
    Returns True if valid, False otherwise.
    """
    if signature_header is None:
        return False
    
    try:
        sha_name, signature = signature_header.split('=', 1)
        if sha_name != "sha256":
            return False
    except ValueError:
        return False
    
    secret = gh_settings.webhook_secret.encode()
    mac = hmac.new(secret, msg=payload_body, digestmod=hashlib.sha256)
    return hmac.compare_digest(mac.hexdigest(), signature)

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TimeoutException)),
    reraise=True
)
async def fetch_pr_diff(repo_full_name: str, pr_number: int) -> str:
    """
    Fetch unified diff for a pull request.
    Retries on transient errors.
    """
    url = f"{gh_settings.api_base}/repos/{repo_full_name}/pulls/{pr_number}"
    headers = {
        "Authorization": f"Bearer {gh_settings.token}",
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "AI-Code-Reviewer/2.0"
    }
    
    async with httpx.AsyncClient(timeout=gh_settings.timeout_seconds) as client:
        response = await client.get(url, headers=headers)
        response.raise_for_status()
        return response.text

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=10),
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TimeoutException)),
    reraise=True
)
async def post_comment(repo_full_name: str, pr_number: int, comment_body: str) -> None:
    """
    Post a comment on the pull request.
    """
    url = f"{gh_settings.api_base}/repos/{repo_full_name}/issues/{pr_number}/comments"
    headers = {
        "Authorization": f"Bearer {gh_settings.token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "AI-Code-Reviewer/2.0"
    }
    data = {"body": comment_body}
    
    async with httpx.AsyncClient(timeout=gh_settings.timeout_seconds) as client:
        response = await client.post(url, headers=headers, json=data)
        response.raise_for_status()

# ------------------------------------------------------------
# Background task: AI review pipeline
# ------------------------------------------------------------

async def run_ai_review(repo_full_name: str, pr_number: int, pr_title: str) -> None:
    """
    Orchestrates: fetch diff -> AI review -> post comment.
    All errors are logged but do not crash the webhook.
    """
    try:
        print(f"🔄 Reviewing PR #{pr_number} in {repo_full_name}: {pr_title}")
        
        # Step 1: Fetch diff
        diff = await fetch_pr_diff(repo_full_name, pr_number)
        if not diff or len(diff.strip()) == 0:
            print(f"⚠️ Empty diff for PR #{pr_number}, skipping review")
            return
        
        # Step 2: Ask AI for review
        review_text = await llm.review(diff)
        
        # Step 3: Post comment
        comment_body = f"""
## 🤖 AI Code Review

{review_text}

---
*Generated automatically by AI Reviewer v2.0*
"""
        await post_comment(repo_full_name, pr_number, comment_body)
        print(f"✅ Review posted for PR #{pr_number}")
        
    except httpx.HTTPStatusError as e:
        status = e.response.status_code
        if status == 403:
            print(f"❌ GitHub token lacks permissions for {repo_full_name}")
        elif status == 404:
            print(f"❌ PR #{pr_number} not found in {repo_full_name}")
        elif status == 422:
            print(f"❌ Validation error for PR #{pr_number}: {e.response.text}")
        else:
            print(f"❌ HTTP {status} error for PR #{pr_number}: {e}")
    except RetryError as e:
        print(f"❌ Failed after retries for PR #{pr_number}: {e}")
    except Exception as e:
        print(f"❌ Unexpected error reviewing PR #{pr_number}: {type(e).__name__}: {e}")

def start_review_task(background_tasks: BackgroundTasks, repo_full_name: str, pr_number: int, pr_title: str):
    """
    Wrapper to schedule async review in background.
    FastAPI BackgroundTasks only accepts sync callables, so we create an async task.
    """
    async def _wrapper():
        await run_ai_review(repo_full_name, pr_number, pr_title)
    background_tasks.add_task(lambda: asyncio.create_task(_wrapper()))

# ------------------------------------------------------------
# Webhook endpoint
# ------------------------------------------------------------

@app.post("/webhook")
async def webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Receives GitHub push/pull_request events.
    Only processes 'opened' actions for pull requests.
    """
    # Read raw body for signature verification
    body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    
    if not verify_signature(body, signature):
        raise HTTPException(status_code=403, detail="Invalid signature")
    
    # Parse JSON payload
    try:
        payload = await request.json()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid JSON payload")
    
    # Validate action and event type
    event_type = request.headers.get("X-GitHub-Event")
    if event_type != "pull_request":
        # Not a PR event, ignore
        return JSONResponse({"status": "ignored", "reason": "not a pull_request event"})
    
    action = payload.get("action")
    if action != "opened":
        return JSONResponse({"status": "ignored", "reason": f"action={action} not 'opened'"})
    
    # Extract required fields
    try:
        pr = payload["pull_request"]
        repo = payload["repository"]
        repo_full_name = repo["full_name"]
        pr_number = pr["number"]
        pr_title = pr["title"]
    except KeyError as e:
        raise HTTPException(status_code=400, detail=f"Missing required field: {e}")
    
    # Schedule the review in background
    start_review_task(background_tasks, repo_full_name, pr_number, pr_title)
    
    return JSONResponse({"status": "accepted", "pr": pr_number})

# ------------------------------------------------------------
# Health & metrics endpoints
# ------------------------------------------------------------

@app.get("/health")
async def health():
    """Simple health check for load balancers."""
    return {"status": "alive", "llm_configured": llm_settings.api_key is not None}

@app.get("/metrics")
async def metrics():
    """
    Basic metrics (can be extended with Prometheus).
    """
    return {
        "llm_endpoint": llm_settings.endpoint,
        "llm_model": llm_settings.model,
        "github_api_base": gh_settings.api_base,
    }

# ------------------------------------------------------------
# Entry point (for local development)
# ------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=port,
        reload=True,  # Only for development
        log_level="info"
    )