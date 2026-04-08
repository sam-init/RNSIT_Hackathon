from fastapi import FastAPI, Request, HTTPException
from threading import Thread
import requests
import os
import hmac
import hashlib

# 🔥 Import your AI agent
from ai_agent import MegaLLM

app = FastAPI()

# ✅ FIXED: correct env variable usage
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

if not WEBHOOK_SECRET:
    raise Exception("❌ WEBHOOK_SECRET not set")

WEBHOOK_SECRET = WEBHOOK_SECRET.encode()

# ✅ Initialize AI agent once (not per request)
llm = MegaLLM()


# 🔐 Verify signature
def verify_signature(payload_body, signature_header):
    if signature_header is None:
        raise HTTPException(status_code=403, detail="Missing signature")

    try:
        sha_name, signature = signature_header.split('=')
    except Exception:
        raise HTTPException(status_code=403, detail="Invalid signature format")

    mac = hmac.new(WEBHOOK_SECRET, msg=payload_body, digestmod=hashlib.sha256)

    if not hmac.compare_digest(mac.hexdigest(), signature):
        raise HTTPException(status_code=403, detail="Invalid signature")


# 🔥 NEW: Fetch PR diff
def fetch_pr_diff(repo, pr_number):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff"  # 👈 IMPORTANT
    }

    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Failed to fetch PR diff: {response.text}")

    return response.text


# 🚀 Background processing
def process_pr(payload):
    try:
        pr = payload["pull_request"]
        repo = payload["repository"]["full_name"]
        pr_number = pr["number"]

        # 🔥 STEP 1: Fetch diff
        diff = fetch_pr_diff(repo, pr_number)

        # 🔥 STEP 2: AI review
        ai_review = llm.review(diff)

        # 🔥 STEP 3: Post comment
        comment_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"

        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }

        # ✅ Clean structured comment
        body = f"""
## 🤖 AI Code Review

{ai_review}

---
*Generated automatically by AI reviewer*
"""

        response = requests.post(comment_url, json={"body": body}, headers=headers)

        if response.status_code != 201:
            print("❌ Failed to post AI review:", response.text)

    except Exception as e:
        print(f"🔥 Error in process_pr: {str(e)}")


# 🌐 Webhook endpoint
@app.post("/webhook")
async def webhook(request: Request):
    try:
        body = await request.body()
        signature = request.headers.get("X-Hub-Signature-256")

        verify_signature(body, signature)

        payload = await request.json()

        if payload.get("action") == "opened":
            Thread(target=process_pr, args=(payload,)).start()

        return {"status": "ok"}

    except Exception as e:
        raise e


# ✅ REQUIRED for Render (fix your port issue)
if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run(app, host="0.0.0.0", port=port)