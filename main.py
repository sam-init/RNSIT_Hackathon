# main.py
import os
import hmac
import hashlib
import logging
from fastapi import FastAPI, Request, Header, HTTPException
from concurrent.futures import ThreadPoolExecutor

from processor import process_pr_event

# ─────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI()

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()

executor = ThreadPoolExecutor(max_workers=4)


# ─────────────────────────────────────────────
# Verify Signature
# ─────────────────────────────────────────────
def verify_signature(body: bytes, signature: str):
    logger.info("🔐 Verifying GitHub signature")

    if not signature:
        logger.error("❌ Missing signature")
        raise HTTPException(403, "Missing signature")

    sha_name, sig = signature.split("=")
    mac = hmac.new(WEBHOOK_SECRET, msg=body, digestmod=hashlib.sha256)

    if not hmac.compare_digest(mac.hexdigest(), sig):
        logger.error("❌ Invalid signature")
        raise HTTPException(403, "Invalid signature")

    logger.info("✅ Signature verified")


# ─────────────────────────────────────────────
# Webhook Endpoint
# ─────────────────────────────────────────────
@app.post("/webhook")
async def webhook(
    request: Request,
    x_hub_signature_256: str = Header(None),
):
    logger.info("📩 Webhook received")

    body = await request.body()

    verify_signature(body, x_hub_signature_256)

    payload = await request.json()
    action = payload.get("action")

    logger.info(f"🔄 Action: {action}")

    if action in ["opened", "synchronize"]:
        logger.info("🚀 Submitting PR for processing")
        executor.submit(process_pr_event, payload)
    else:
        logger.info("⏭️ Ignored event")

    return {"status": "ok"}