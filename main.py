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
        pr_number = pr["number"]

        print(f"📦 Repo: {repo}")
        print(f"🔢 PR Number: {pr_number}")

        # 🔥 STEP 1: Fetch PR files (diff)
        files_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"

        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }

        print("📥 Fetching PR files...")

        response = requests.get(files_url, headers=headers)

        print(f"📡 Files API Status: {response.status_code}")

        if response.status_code != 200:
            print("❌ Failed to fetch PR files")
            print(response.text)
            return

        files = response.json()

        print(f"📄 Total files changed: {len(files)}")

        # 🔥 STEP 2: Extract changes
        all_changes = ""

        for file in files:
            filename = file["filename"]
            patch = file.get("patch", "")

            print(f"\n📁 File: {filename}")
            print(f"✏️ Changes:\n{patch[:500]}")  # preview

            all_changes += f"\nFile: {filename}\n{patch}\n"

        # 🔥 STEP 3: (Temporary AI simulation)
        if "password" in all_changes.lower():
            review = "🔴 Potential security issue: hardcoded password detected."
        else:
            review = "✅ No obvious issues detected."

        # 🔥 STEP 4: Post comment
        comment_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"

        print("📤 Sending review comment...")

        response = requests.post(
            comment_url,
            json={"body": review},
            headers=headers
        )

        print(f"📡 Comment Status: {response.status_code}")
        print(f"📡 Response: {response.text}")

        if response.status_code == 201:
            print("✅ Comment posted successfully")
        else:
            print("❌ Failed to post comment")

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

        if action in ["opened", "synchronize", "reopened"]:
            print("🟢 PR Opened → Starting background job")
            Thread(target=process_pr, args=(payload,)).start()
        else:
            print("⚪ Ignored event")

        print("========== ✅ WEBHOOK HANDLED ==========\n")

        return {"status": "ok"}

    except Exception as e:
        print(f"🔥 Webhook Error: {str(e)}")
        raise e