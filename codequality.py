import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx


NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"
MIN_CONFIDENCE = 0.7


def _extract_file_diff(
    diff_text: str, filename: str
) -> Tuple[str, List[int], List[Tuple[int, str]]]:
    target_lines: List[str] = []
    added_line_numbers: List[int] = []
    added_lines: List[Tuple[int, str]] = []

    in_target_file = False
    in_hunk = False
    new_line_no: Optional[int] = None

    diff_file_pattern = re.compile(r"^diff --git a/(.+?) b/(.+)$")
    hunk_pattern = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")

    for line in diff_text.splitlines():
        if line.startswith("diff --git "):
            match = diff_file_pattern.match(line)
            in_target_file = bool(match and match.group(2) == filename)
            in_hunk = False
            new_line_no = None
            if in_target_file:
                target_lines.append(line)
            continue

        if line.startswith("+++ b/"):
            current_file = line[len("+++ b/") :]
            in_target_file = current_file == filename
            if in_target_file:
                target_lines.append(line)
            continue

        if not in_target_file:
            continue

        target_lines.append(line)

        if line.startswith("@@"):
            in_hunk = True
            match = hunk_pattern.match(line)
            new_line_no = int(match.group(1)) if match else None
            continue

        if not in_hunk:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            if new_line_no is not None:
                added_line_numbers.append(new_line_no)
                added_lines.append((new_line_no, line[1:]))
                new_line_no += 1
            continue

        if line.startswith("-") and not line.startswith("---"):
            continue

        if line.startswith("\\"):
            continue

        if new_line_no is not None:
            new_line_no += 1

    return "\n".join(target_lines), sorted(set(added_line_numbers)), added_lines


def _clean_json_content(content: str) -> str:
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _parse_model_json(content: str) -> List[Dict[str, Any]]:
    text = _clean_json_content(content)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1 or end < start:
            return []
        try:
            data = json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return []

    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]

    if isinstance(data, dict):
        for key in ("results", "comments", "issues", "output"):
            if isinstance(data.get(key), list):
                return [item for item in data[key] if isinstance(item, dict)]
    return []


def _line_is_valid(line: int, valid_line_set: Set[int]) -> bool:
    return line in valid_line_set


def _body_is_valid(body: str) -> bool:
    if not body.startswith("⚠️ "):
        return False
    if "\n\nExplanation:" not in body:
        return False
    if "\n\nSuggestion:" not in body:
        return False
    return True


def _validate_and_normalize_results(
    raw_results: List[Dict[str, Any]], filename: str, valid_lines: List[int]
) -> List[Dict[str, Any]]:
    final_results: List[Dict[str, Any]] = []
    seen = set()
    valid_line_set = set(valid_lines)

    for item in raw_results:
        issue_type = item.get("type")
        if issue_type not in {"quality", "performance"}:
            continue

        body = item.get("body")
        if not isinstance(body, str):
            continue
        body = body.strip()
        if not _body_is_valid(body):
            continue

        try:
            confidence = float(item.get("confidence", 0.0))
        except (TypeError, ValueError):
            continue
        if confidence < MIN_CONFIDENCE:
            continue
        confidence = max(0.0, min(1.0, confidence))

        try:
            raw_line = int(item.get("line"))
        except (TypeError, ValueError):
            continue
        if not _line_is_valid(raw_line, valid_line_set):
            continue
        line = raw_line

        output = {
            "agent": "code_quality",
            "type": issue_type,
            "file": filename,
            "line": line,
            "body": body,
            "confidence": confidence,
        }

        dedupe_key = (output["type"], output["file"], output["line"], output["body"])
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        final_results.append(output)

    return final_results


def _build_prompt(
    filename: str,
    commit_sha: Optional[str],
    file_diff: str,
    added_lines: List[Tuple[int, str]],
    valid_lines: List[int],
) -> List[Dict[str, str]]:
    line_catalog = "\n".join(
        f"{line_no}: {code[:200]}" for line_no, code in added_lines[:400]
    )
    valid_line_json = json.dumps(valid_lines)

    system_prompt = (
        "You are a pull request review agent focused ONLY on code quality and performance. "
        "Never report security issues. Never report architecture issues. "
        "Return strictly valid JSON list and nothing else."
    )

    user_prompt = (
        f"Target file: {filename}\n"
        f"Commit SHA: {commit_sha or ''}\n\n"
        "Analyze only:\n"
        "- code quality issues (bad practices, duplication, naming, dead code)\n"
        "- performance inefficiencies (loops, unnecessary operations, complexity)\n\n"
        "Do not analyze:\n"
        "- security issues\n"
        "- architecture issues\n\n"
        "Rules:\n"
        "1. Use only these line numbers for comments: "
        f"{valid_line_json}\n"
        "2. Return only high-confidence issues.\n"
        "3. Keep output minimal and actionable.\n"
        "4. Output must be a JSON list with objects using exactly these keys:\n"
        '   ["agent","type","file","line","body","confidence"]\n'
        "5. agent must be \"code_quality\".\n"
        "6. type must be \"quality\" or \"performance\".\n"
        f"7. file must be exactly \"{filename}\".\n"
        "8. body format must be exactly:\n"
        "   ⚠️ <issue title>\\n\\nExplanation: ...\\n\\nSuggestion: ...\n"
        "9. confidence must be a number from 0.0 to 1.0.\n"
        "10. If no high-confidence issue, return [] exactly.\n\n"
        "Added lines (line: code):\n"
        f"{line_catalog}\n\n"
        "Unified diff for target file:\n"
        f"{file_diff}"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


class CodeQualityAgent:
    @staticmethod
    def analyze(
        diff: str, filename: str, commit_sha: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        if not diff or not filename:
            return []

        try:
            api_key = os.environ["NVIDIA_API_KEY"]
        except KeyError:
            return []

        file_diff, valid_lines, added_lines = _extract_file_diff(diff, filename)
        if not file_diff or not valid_lines:
            return []

        messages = _build_prompt(
            filename=filename,
            commit_sha=commit_sha,
            file_diff=file_diff,
            added_lines=added_lines,
            valid_lines=valid_lines,
        )

        payload = {
            "model": os.getenv("NVIDIA_MODEL", DEFAULT_MODEL),
            "messages": messages,
            "temperature": 0.2,
        }

        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }

        try:
            with httpx.Client(timeout=30.0) as client:
                response = client.post(NVIDIA_API_URL, headers=headers, json=payload)
                response.raise_for_status()
                response_json = response.json()
        except Exception:
            return []

        content = (
            response_json.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        if not isinstance(content, str) or not content.strip():
            return []

        raw_results = _parse_model_json(content)
        return _validate_and_normalize_results(raw_results, filename, valid_lines)

    @staticmethod
    def scan(
        diff: str, filename: str, commit_sha: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        return CodeQualityAgent.analyze(diff=diff, filename=filename, commit_sha=commit_sha)


def analyze_code_quality(
    diff: str, filename: str, commit_sha: Optional[str] = None
) -> List[Dict[str, Any]]:
    return CodeQualityAgent.analyze(diff=diff, filename=filename, commit_sha=commit_sha)
