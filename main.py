from fastapi import FastAPI, Request, HTTPException
from threading import Thread
import requests
import os
import hmac
import hashlib

app = FastAPI()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

if not WEBHOOK_SECRET:
    raise Exception("❌ WEBHOOK_SECRET not set")

WEBHOOK_SECRET = WEBHOOK_SECRET.encode()


# 🔐 Verify signature
def verify_signature(payload_body, signature_header):
    print("🔍 Verifying signature...")

    if signature_header is None:
        print("❌ Missing signature header")
        raise HTTPException(status_code=403, detail="Missing signature")

    try:
        sha_name, signature = signature_header.split('=')
    except Exception:
        print("❌ Invalid signature format")
        raise HTTPException(status_code=403, detail="Invalid signature format")

    mac = hmac.new(WEBHOOK_SECRET, msg=payload_body, digestmod=hashlib.sha256)

    if not hmac.compare_digest(mac.hexdigest(), signature):
        print("❌ Signature mismatch")
        raise HTTPException(status_code=403, detail="Invalid signature")

    print("✅ Signature verified")


# 🚀 Background processing
def process_pr(payload):
    print("🚀 Processing PR in background...")

    try:
        pr = payload["pull_request"]
        repo = payload["repository"]["full_name"]
        issue_number = pr["number"]

        print(f"📦 Repo: {repo}")
        print(f"🔢 PR Number: {issue_number}")

        comment = "✅ AI Review Started..."

        url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"

        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }

        print("📤 Sending comment to GitHub...")

        response = requests.post(url, json={"body": comment}, headers=headers)

        print(f"📡 GitHub Response Status: {response.status_code}")
        print(f"📡 GitHub Response Body: {response.text}")

        if response.status_code != 201:
            print("❌ Failed to post comment")

        else:
            print("✅ Comment posted successfully")

    except Exception as e:
        print(f"🔥 Error in process_pr: {str(e)}")


# 🌐 Webhook endpoint
@app.post("/webhook")
async def webhook(request: Request):
    print("\n========== 🔔 WEBHOOK RECEIVED ==========")

    try:
        body = await request.body()
        print("📥 Raw body received")

        signature = request.headers.get("X-Hub-Signature-256")
        print(f"🔑 Signature header: {signature}")

        # Verify request
        verify_signature(body, signature)

        payload = await request.json()
        print("📦 Payload parsed")

        action = payload.get("action")
        print(f"⚡ Action: {action}")

        if action == "opened":
            print("🟢 PR Opened → Starting background job")
            Thread(target=process_pr, args=(payload,)).start()
        else:
            print("⚪ Ignored event")

        print("========== ✅ WEBHOOK HANDLED ==========\n")

        return {"status": "ok"}

    except Exception as e:
        print(f"🔥 Webhook Error: {str(e)}")
        raise e