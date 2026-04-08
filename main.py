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
        commit_id = pr["head"]["sha"]

        print(f"📦 Repo: {repo}")
        print(f"🔢 PR Number: {pr_number}")
        print(f"🔗 Commit ID: {commit_id}")

        headers = {
            "Authorization": f"Bearer {GITHUB_TOKEN}",
            "Accept": "application/vnd.github+json"
        }

        # 🔥 STEP 1: Fetch PR files
        files_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/files"

        print("📥 Fetching PR files...")
        response = requests.get(files_url, headers=headers)

        print(f"📡 Files API Status: {response.status_code}")

        if response.status_code != 200:
            print("❌ Failed to fetch PR files")
            print(response.text)
            return

        files = response.json()
        print(f"📄 Total files changed: {len(files)}")

        issues = []
        all_changes = ""

        # 🔥 STEP 2: Analyze changes
        for file in files:
            filename = file["filename"]
            patch = file.get("patch", "")

            print(f"\n📁 File: {filename}")
            print(f"✏️ Changes:\n{patch[:300]}")

            all_changes += f"\nFile: {filename}\n{patch}\n"

            # 🔥 Simple issue detection (upgrade later with AI)
            if "def a" in patch:
                issues.append({
                    "file": filename,
                    "line": 4,  # temp approximation
                    "message": "⚠️ Function name 'a' is too generic and may conflict with variables."
                })

            if "password" in patch.lower():
                issues.append({
                    "file": filename,
                    "line": 1,
                    "message": "🔴 Potential security issue: hardcoded password detected."
                })

        # 🔥 STEP 3: Post INLINE comments
        inline_url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/comments"

        for issue in issues:
            print(f"📌 Posting inline comment on {issue['file']}")

            data = {
                "body": issue["message"],
                "commit_id": commit_id,
                "path": issue["file"],
                "line": issue["line"]
            }

            res = requests.post(inline_url, json=data, headers=headers)

            print(f"📡 Inline Status: {res.status_code}")
            print(res.text)

        # 🔥 STEP 4: Summary comment
        summary = f"""
## 🤖 AI Review Summary

- Files changed: {len(files)}
- Issues found: {len(issues)}

"""

        if len(issues) == 0:
            summary += "✅ No major issues detected."
        else:
            summary += "⚠️ Issues detected. Check inline comments."

        summary_url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"

        print("📤 Posting summary comment...")

        res = requests.post(summary_url, json={"body": summary}, headers=headers)

        print(f"📡 Summary Status: {res.status_code}")
        print(res.text)

        if res.status_code == 201:
            print("✅ Summary posted successfully")
        else:
            print("❌ Failed to post summary")

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

        verify_signature(body, signature)

        payload = await request.json()
        print("📦 Payload parsed")

        action = payload.get("action")
        print(f"⚡ Action: {action}")

        if action in ["opened", "synchronize", "reopened"]:
            print("🟢 Triggering background review...")
            Thread(target=process_pr, args=(payload,)).start()
        else:
            print("⚪ Ignored event")

        print("========== ✅ WEBHOOK HANDLED ==========\n")

        return {"status": "ok"}

    except Exception as e:
        print(f"🔥 Webhook Error: {str(e)}")
        raise e