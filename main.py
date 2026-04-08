from fastapi import FastAPI, Request
from threading import Thread
import requests
import os

app = FastAPI()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

def process_pr(payload):
    pr = payload["pull_request"]
    repo = payload["repository"]["full_name"]
    issue_number = pr["number"]

    comment = "✅ AI Review Started..."

    url = f"https://api.github.com/repos/{repo}/issues/{issue_number}/comments"

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json"
    }

    requests.post(url, json={"body": comment}, headers=headers)


@app.post("/webhook")
async def webhook(request: Request):
    payload = await request.json()

    if payload.get("action") == "opened":
        Thread(target=process_pr, args=(payload,)).start()

    return {"status": "ok"}