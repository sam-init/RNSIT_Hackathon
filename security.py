# security.py (or ai_agent.py)

import os
import re
import httpx
from dataclasses import dataclass
from typing import List

LLM_API_KEY = os.environ["LLM_API_KEY"]


# ─────────────────────────────────────────────
# Inline Comment Model
# ─────────────────────────────────────────────
@dataclass
class InlineComment:
    path: str
    line: int
    body: str
    severity: str = "medium"

    def to_github_payload(self):
        return {
            "path": self.path,
            "line": self.line,
            "side": "RIGHT",
            "body": self.body,
        }


# ─────────────────────────────────────────────
# Diff Parser
# ─────────────────────────────────────────────
class DiffParser:
    @staticmethod
    def parse(diff_text: str):
        files = {}
        current_file = None
        line_no = 0

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line.replace("+++ b/", "")
                files[current_file] = []

            elif line.startswith("@@"):
                parts = line.split(" ")
                new_line_info = parts[2]
                start = int(new_line_info.split(",")[0][1:])
                line_no = start

            elif current_file and line.startswith("+"):
                files[current_file].append((line_no, line[1:]))
                line_no += 1
            elif current_file and not line.startswith("-"):
                line_no += 1

        return files


# ─────────────────────────────────────────────
# FAST SECURITY PATTERNS (KEEP THIS)
# ─────────────────────────────────────────────
PATTERNS = [
    (r'api[_-]?key\s*=\s*["\'].*["\']', "Hardcoded API Key", "Use env variables"),
    (r'password\s*=\s*["\'].*["\']', "Hardcoded password", "Use secret manager"),
    (r'eval\(', "Use of eval()", "Avoid eval"),
    (r'subprocess.*shell=True', "Shell injection risk", "Use shell=False"),
]


# ─────────────────────────────────────────────
# LLM ANALYSIS
# ─────────────────────────────────────────────
def llm_security_analysis(code: str):
    if not LLM_API_KEY:
        return []

    try:
        response = httpx.post(
            "https://api.openai.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "gpt-4o-mini",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security code reviewer. Return ONLY JSON."
                    },
                    {
                        "role": "user",
                        "content": f"""
Analyze this code for security vulnerabilities.

Return JSON array:
[
  {{
    "severity": "high|medium|low",
    "issue": "short description",
    "fix": "suggested fix"
  }}
]

Code:
{code}
"""
                    }
                ],
                "temperature": 0.2,
            },
            timeout=20
        )

        data = response.json()
        content = data["choices"][0]["message"]["content"]

        return eval(content) if content.startswith("[") else []

    except Exception:
        return []


# ─────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────
class SecurityScanner:

    @staticmethod
    def scan(diff_text: str) -> List[InlineComment]:
        parsed = DiffParser.parse(diff_text)
        results = []

        for file, lines in parsed.items():
            for line_no, code in lines:

                # 🔹 1. Fast regex scan
                for pattern, msg, fix in PATTERNS:
                    if re.search(pattern, code):
                        results.append(
                            InlineComment(
                                path=file,
                                line=line_no,
                                severity="high",
                                body=f"🚨 {msg}\n\n`{code.strip()}`\n\n💡 Fix: {fix}"
                            )
                        )

                # 🔹 2. LLM scan (NEW 🔥)
                llm_results = llm_security_analysis(code)

                for issue in llm_results:
                    results.append(
                        InlineComment(
                            path=file,
                            line=line_no,
                            severity=issue.get("severity", "medium"),
                            body=(
                                f"🤖 **AI Security Insight**\n\n"
                                f"⚠️ {issue.get('issue')}\n\n"
                                f"`{code.strip()}`\n\n"
                                f"💡 Fix: {issue.get('fix')}"
                            )
                        )
                    )

        return results