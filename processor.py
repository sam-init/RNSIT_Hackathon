# processor.py
import os
import httpx
import logging

from security import SecurityScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("processor")

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]


# ─────────────────────────────────────────────
# Get Diff (CORRECT METHOD)
# ─────────────────────────────────────────────
def get_diff(repo, pr_number):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
    }

    response = httpx.get(url, headers=headers)

    if response.status_code != 200:
        logger.error(f"Diff fetch failed: {response.text}")
        return ""

    return response.text


# ─────────────────────────────────────────────
# Post Review
# ─────────────────────────────────────────────
def post_review(repo, pr_number, commit_id, comments):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"

    payload = {
        "commit_id": commit_id,
        "event": "COMMENT",
        "comments": [c.to_github_payload() for c in comments],
    }

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }

    response = httpx.post(url, json=payload, headers=headers)

    if response.status_code not in [200, 201]:
        logger.error(f"GitHub error: {response.text}")


# ─────────────────────────────────────────────
# MAIN PROCESSOR (IMPORTANT: NO GLOBAL CODE)
# ─────────────────────────────────────────────
def process_pr_event(payload):
    logger.info("Processing PR")

    try:
        pr = payload["pull_request"]

        repo = payload["repository"]["full_name"]
        pr_number = pr["number"]
        commit_id = pr["head"]["sha"]

        # ✅ Diff fetch INSIDE function
        diff = get_diff(repo, pr_number)

        if not diff:
            logger.warning("Empty diff")
            return

        # Run scanner
        comments = SecurityScanner.scan(diff)

        logger.info(f"Found {len(comments)} issues")

        if comments:
            post_review(repo, pr_number, commit_id, comments)

    except Exception as e:
        logger.error(f"Processor error: {e}")