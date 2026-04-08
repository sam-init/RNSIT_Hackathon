# processor.py
import os
import httpx
import logging

from security import SecurityScanner

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("processor")

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]


# ─────────────────────────────────────────────
# Get Diff (FIXED ✅)
# ─────────────────────────────────────────────
def get_diff(repo, pr_number):
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"

    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
    }

    logger.info(f"🌐 Fetching diff from API: {url}")

    response = httpx.get(url, headers=headers)

    if response.status_code != 200:
        logger.error(f"❌ Diff fetch failed: {response.text}")
        return ""

    logger.info(f"✅ Diff fetched ({len(response.text)} chars)")
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

    logger.info(f"📤 Posting {len(comments)} comments")

    response = httpx.post(url, json=payload, headers=headers)

    if response.status_code not in [200, 201]:
        logger.error(f"❌ GitHub error: {response.text}")
    else:
        logger.info("✅ Review posted")


# ─────────────────────────────────────────────
# PROCESSOR (MAIN LOGIC)
# ─────────────────────────────────────────────
def process_pr_event(payload):
    logger.info("🔍 Processing PR")

    try:
        pr = payload["pull_request"]

        repo = payload["repository"]["full_name"]
        pr_number = pr["number"]
        commit_id = pr["head"]["sha"]

        logger.info(f"📦 Repo: {repo}")
        logger.info(f"🔢 PR: {pr_number}")

        # ✅ FIXED DIFF FETCH
        diff = get_diff(repo, pr_number)

        if not diff:
            logger.warning("⚠️ Empty diff")
            return

        logger.info(f"📄 Diff preview:\n{diff[:300]}")

        # Run Security Agent
        comments = SecurityScanner.scan(diff)

        logger.info(f"🧠 Found {len(comments)} issues")

        if comments:
            post_review(repo, pr_number, commit_id, comments)
        else:
            logger.info("✅ No issues found")

    except Exception as e:
        logger.error(f"🔥 Error: {e}")