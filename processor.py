# processor.py
import httpx
import os
import logging

from security import SecurityScanner

# ─────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("processor")

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]


# ─────────────────────────────────────────────
# GitHub API
# ─────────────────────────────────────────────
def get_diff(diff_url):
    logger.info(f"🌐 Fetching diff from: {diff_url}")
    try:
        headers = {"Accept": "application/vnd.github.diff"}
        response = httpx.get(diff_url, headers=headers)

        logger.info(f"📡 Diff fetch status: {response.status_code}")

        return response.text
    except Exception as e:
        logger.error(f"❌ Failed to fetch diff: {e}")
        return ""


def post_review(repo, pr_number, commit_id, comments):
    logger.info(f"📤 Posting review to PR #{pr_number} ({repo})")
    logger.info(f"📝 Total comments: {len(comments)}")

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

    try:
        response = httpx.post(url, json=payload, headers=headers)

        logger.info(f"📡 GitHub response: {response.status_code}")

        if response.status_code not in [200, 201]:
            logger.error(f"❌ GitHub error: {response.text}")
        else:
            logger.info("✅ Review posted successfully")

    except Exception as e:
        logger.error(f"❌ Failed to post review: {e}")


# ─────────────────────────────────────────────
# AGENTS
# ─────────────────────────────────────────────
AGENTS = [
    SecurityScanner,
]


# ─────────────────────────────────────────────
# MAIN PROCESSOR
# ─────────────────────────────────────────────
def process_pr_event(payload):
    logger.info("🔍 Starting PR processing")

    try:
        pr = payload["pull_request"]

        repo = payload["repository"]["full_name"]
        pr_number = pr["number"]
        diff_url = pr["diff_url"]
        commit_id = pr["head"]["sha"]

        logger.info(f"📦 Repo: {repo}")
        logger.info(f"🔢 PR Number: {pr_number}")
        logger.info(f"🔀 Commit ID: {commit_id[:7]}")

        # Step 1: Fetch diff
        diff = get_diff(diff_url)

        if not diff:
            logger.warning("⚠️ Empty diff, skipping")
            return

        logger.info(f"📄 Diff size: {len(diff)} chars")

        all_comments = []

        # Step 2: Run Agents
        for agent in AGENTS:
            logger.info(f"🤖 Running agent: {agent.__name__}")

            try:
                comments = agent.scan(diff)

                logger.info(f"🧠 {agent.__name__} found {len(comments)} issues")

                all_comments.extend(comments)

            except Exception as e:
                logger.error(f"❌ Agent {agent.__name__} failed: {e}")

        # Step 3: Post Review
        if all_comments:
            logger.info("📤 Sending comments to GitHub")
            post_review(repo, pr_number, commit_id, all_comments)
        else:
            logger.info("✅ No issues found")

    except Exception as e:
        logger.error(f"🔥 Critical failure in PR processing: {e}")