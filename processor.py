# processor.py
import httpx
import os
import logging

from security import SecurityScanner
from codequality import CodeQualityAgent

# ─────────────────────────────────────────────
# Logging Setup
# ─────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("processor")

GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]


def extract_changed_files(diff_text):
    files = []
    seen = set()

    for line in diff_text.splitlines():
        if not line.startswith("+++ b/"):
            continue

        path = line.replace("+++ b/", "", 1).strip()
        if path == "/dev/null" or not path or path in seen:
            continue

        seen.add(path)
        files.append(path)

    return files


def to_review_payload(comment):
    if hasattr(comment, "to_github_payload"):
        return comment.to_github_payload()

    if isinstance(comment, dict):
        path = comment.get("file")
        line = comment.get("line")
        body = comment.get("body")

        if not isinstance(path, str) or not path.strip():
            return None
        if not isinstance(body, str) or not body.strip():
            return None
        if not isinstance(line, int) or line <= 0:
            return None

        return {
            "path": path,
            "line": line,
            "side": "RIGHT",
            "body": body,
        }

    return None


# ─────────────────────────────────────────────
# GitHub API
# ─────────────────────────────────────────────
diff = get_diff(f"https://api.github.com/repos/{repo}/pulls/{pr_number}")
def get_diff(pr_api_url):
    headers = {
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3.diff",
    }

    response = httpx.get(pr_api_url, headers=headers)

    if response.status_code != 200:
        print("❌ Failed to fetch diff:", response.text)
        return ""

    return response.text


def post_review(repo, pr_number, commit_id, comments):
    logger.info(f"📤 Posting review to PR #{pr_number} ({repo})")
    logger.info(f"📝 Total comments: {len(comments)}")

    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}/reviews"

    review_comments = []
    for c in comments:
        payload_comment = to_review_payload(c)
        if payload_comment:
            review_comments.append(payload_comment)

    if not review_comments:
        logger.info("⚠️ No valid comments to post after normalization")
        return

    payload = {
        "commit_id": commit_id,
        "event": "COMMENT",
        "comments": review_comments,
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
    CodeQualityAgent,
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
        changed_files = extract_changed_files(diff)
        logger.info(f"📂 Changed files in diff: {len(changed_files)}")

        # Step 2: Run Agents
        for agent in AGENTS:
            logger.info(f"🤖 Running agent: {agent.__name__}")

            try:
                comments = []

                if agent is CodeQualityAgent:
                    for filename in changed_files:
                        comments.extend(
                            agent.scan(diff=diff, filename=filename, commit_sha=commit_id)
                        )
                else:
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
