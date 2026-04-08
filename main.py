from fastapi import FastAPI, Request, HTTPException
from threading import Thread
import requests
import os
import hmac
import hashlib

# !pip install llama-cpp-python
from llama_cpp import Llama

app = FastAPI()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET")

if not WEBHOOK_SECRET:
    raise Exception("❌ WEBHOOK_SECRET not set")

WEBHOOK_SECRET = WEBHOOK_SECRET.encode()

# 🤖 Load WhiteRabbitNeo cybersecurity model
print("🔄 Loading WhiteRabbitNeo model...")
llm = Llama.from_pretrained(
    repo_id="bartowski/WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-GGUF",
    filename="WhiteRabbitNeo_WhiteRabbitNeo-V3-7B-IQ2_M.gguf",
)
print("✅ Model loaded successfully")


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


# 🛡️ Analyze code using WhiteRabbitNeo for cybersecurity issues
def analyze_with_llm(filename, patch):
    print(f"🤖 Running LLM analysis on {filename}...")

    prompt = f"""You are a cybersecurity code reviewer. Analyze the following code diff for security vulnerabilities, bad practices, and potential exploits.

File: {filename}
Diff:
{patch}

Respond with a concise list of security issues found (if any). For each issue include:
- Issue type (e.g., Injection, Hardcoded Secret, Insecure Function)
- Line reference if visible
- Brief explanation

If no issues are found, respond with: NO_ISSUES"""

    response = llm(
        prompt,
        max_tokens=512,
        stop=["</s>", "\n\n\n"],
        echo=False
    )

    result = response["choices"][0]["text"].strip()
    print(f"🧠 LLM Response for {filename}:\n{result}")
    return result


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

        print("📤 Sending comment to GitHub...")

        response = requests.post(url, json={"body": comment}, headers=headers)

        print(f"📡 GitHub Response Status: {response.status_code}")
        print(f"📡 GitHub Response Body: {response.text}")

        if response.status_code != 201:
            print("❌ Failed to post comment")

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