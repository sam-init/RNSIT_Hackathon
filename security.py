# ai_agent.py
from dataclasses import dataclass
from typing import List
import re


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
# Diff Parser (minimal)
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
                new_line_info = parts[2]  # +start,count
                start = int(new_line_info.split(",")[0][1:])
                line_no = start

            elif current_file and line.startswith("+"):
                files[current_file].append((line_no, line[1:]))
                line_no += 1
            elif current_file and not line.startswith("-"):
                line_no += 1

        return files


# ─────────────────────────────────────────────
# Security Patterns
# ─────────────────────────────────────────────
PATTERNS = [
    {
        "regex": r'api[_-]?key\s*=\s*["\'].*["\']',
        "severity": "critical",
        "msg": "Hardcoded API Key detected",
        "fix": "Use environment variables (os.getenv)"
    },
    {
        "regex": r'password\s*=\s*["\'].*["\']',
        "severity": "critical",
        "msg": "Hardcoded password detected",
        "fix": "Store secrets securely (env/secret manager)"
    },
    {
        "regex": r'execute\(f".*{.*}.*"\)',
        "severity": "high",
        "msg": "Possible SQL Injection",
        "fix": "Use parameterized queries"
    },
    {
        "regex": r'subprocess.*shell=True',
        "severity": "high",
        "msg": "Shell injection risk",
        "fix": "Use shell=False and pass args as list"
    },
    {
        "regex": r'eval\(',
        "severity": "high",
        "msg": "Use of eval() is dangerous",
        "fix": "Avoid eval, use safer parsing"
    },
    {
        "regex": r'hashlib\.md5',
        "severity": "medium",
        "msg": "Weak hashing algorithm (MD5)",
        "fix": "Use sha256 or bcrypt"
    },
]


# ─────────────────────────────────────────────
# Dependency Scanner
# ─────────────────────────────────────────────
def check_dependencies(file_path: str, line: str):
    comments = []

    vulnerable_libs = {
        "django==1.2": "Upgrade Django (known CVEs)",
        "flask==0.12": "Upgrade Flask (security issues)",
        "requests==2.19.0": "Upgrade requests (CVE present)",
    }

    for lib, fix in vulnerable_libs.items():
        if lib in line:
            comments.append((lib, fix))

    return comments


# ─────────────────────────────────────────────
# Main Security Scanner
# ─────────────────────────────────────────────
class SecurityScanner:

    @staticmethod
    def scan(diff_text: str) -> List[InlineComment]:
        parsed = DiffParser.parse(diff_text)
        results = []

        for file, lines in parsed.items():
            for line_no, code in lines:

                # Pattern scan
                for p in PATTERNS:
                    if re.search(p["regex"], code):
                        results.append(
                            InlineComment(
                                path=file,
                                line=line_no,
                                severity=p["severity"],
                                body=(
                                    f"⚠️ **{p['severity'].upper()}**: {p['msg']}\n\n"
                                    f"`{code.strip()}`\n\n"
                                    f"💡 Fix: {p['fix']}"
                                )
                            )
                        )

                # Dependency scan
                if "requirements.txt" in file or "package.json" in file:
                    deps = check_dependencies(file, code)
                    for lib, fix in deps:
                        results.append(
                            InlineComment(
                                path=file,
                                line=line_no,
                                severity="high",
                                body=(
                                    f"🚨 Vulnerable dependency: `{lib}`\n\n"
                                    f"💡 Fix: {fix}"
                                )
                            )
                        )

        return results