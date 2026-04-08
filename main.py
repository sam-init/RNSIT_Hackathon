# main.py
import os
import hmac
import hashlib
import logging
from fastapi import FastAPI, Request, Header, HTTPException
from concurrent.futures import ThreadPoolExecutor

from processor import process_pr_event

# ─────────────────────────────────────────────
# Setup
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("main")

app = FastAPI()  # ✅ REQUIRED FOR UVICORN

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()
executor = ThreadPoolExecutor(max_workers=4)


# ─────────────────────────────────────────────
# Signature Verification
# ─────────────────────────────────────────────
def verify_signature(body: bytes, signature: str):
    if not signature:
        raise HTTPException(403, "Missing signature")

    try:
        sha_name, sig = signature.split("=")
    except Exception:
        raise HTTPException(403, "Invalid signature format")

    mac = hmac.new(WEBHOOK_SECRET, msg=body, digestmod=hashlib.sha256)

    if not hmac.compare_digest(mac.hexdigest(), sig):
        raise HTTPException(403, "Invalid signature")


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

    logger.info(f"Action: {action}")

    if action in ["opened", "synchronize"]:
        logger.info("Sending PR to processor")
        executor.submit(process_pr_event, payload)

    return {"status": "ok"}