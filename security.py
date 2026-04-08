# security.py
import os
import re
import httpx
from dataclasses import dataclass
from typing import List

LLM_API_KEY = os.environ["LLM_API_KEY"]


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
    def parse(diff_text):
        files = {}
        current_file = None
        line_no = 0

        for line in diff_text.splitlines():
            if line.startswith("+++ b/"):
                current_file = line.replace("+++ b/", "")
                files[current_file] = []

            elif line.startswith("@@"):
                parts = line.split(" ")
                start = int(parts[2].split(",")[0][1:])
                line_no = start

            elif current_file and line.startswith("+"):
                files[current_file].append((line_no, line[1:]))
                line_no += 1
            elif current_file and not line.startswith("-"):
                line_no += 1

        return files


# ─────────────────────────────────────────────
# Regex Patterns
# ─────────────────────────────────────────────
PATTERNS = [
    (r'api[_-]?key\s*=\s*["\'].*["\']', "Hardcoded API key", "Use env variables"),
    (r'password\s*=\s*["\'].*["\']', "Hardcoded password", "Use secret manager"),
    (r'eval\(', "Use of eval()", "Avoid eval"),
    (r'subprocess.*shell=True', "Shell injection", "Use shell=False"),
    (r'<script>', "Possible XSS", "Sanitize input"),
]


# ─────────────────────────────────────────────
# LLM ANALYSIS
# ─────────────────────────────────────────────
def llm_analysis(code):
    if not LLM_API_KEY:
        return []

    try:
        response = httpx.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {LLM_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": "meta/llama-3.1-8b-instruct",  # ✅ NVIDIA model
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a security code reviewer. Return ONLY JSON."
                    },
                    {
                        "role": "user",
                        "content": f"""
Analyze this code for security vulnerabilities.

Return JSON:
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
                "max_tokens": 512
            },
            timeout=20
        )

        data = response.json()

        content = data["choices"][0]["message"]["content"]

        # safer parsing
        import json as pyjson
        return pyjson.loads(content) if content.startswith("[") else []

    except Exception as e:
        print("LLM Error:", e)
        return []


# ─────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────
class SecurityScanner:

    @staticmethod
    def scan(diff_text) -> List[InlineComment]:
        parsed = DiffParser.parse(diff_text)
        results = []

        for file, lines in parsed.items():
            for line_no, code in lines:

                # Regex scan
                for pattern, msg, fix in PATTERNS:
                    if re.search(pattern, code):
                        results.append(
                            InlineComment(
                                path=file,
                                line=line_no,
                                body=f"🚨 {msg}\n\n`{code}`\n\n💡 Fix: {fix}"
                            )
                        )

                # LLM scan
                llm_results = llm_analysis(code)

                for issue in llm_results:
                    results.append(
                        InlineComment(
                            path=file,
                            line=line_no,
                            body=(
                                f"🤖 AI Insight\n\n"
                                f"{issue.get('issue')}\n\n"
                                f"`{code}`\n\n"
                                f"💡 {issue.get('fix')}"
                            )
                        )
                    )

        return results