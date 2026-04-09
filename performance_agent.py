# performance_agent.py — Performance Analysis Agent
# ====================================================
#
# Detects performance issues in PR diffs:
#   - unnecessary loops / O(n²) where O(n) is possible
#   - repeated lookups in lists (should use set/dict)
#   - redundant computations inside loops
#   - blocking I/O in hot paths
#   - memory-inefficient patterns
#   - string concatenation in loops
#   - sorting inside loops
#
# Integrates with the main.py pipeline via process_pr().
# Uses the same NVIDIA LLM endpoint as ai_agent.py (MegaLLM).
#
# Usage:
#   from performance_agent import PerformanceAgent, analyze_performance
#   results = PerformanceAgent.analyze(diff, filename)
#   results = analyze_performance(diff, filename)  # module-level alias

import json
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx
from rag.grounding import augment_prompt_with_context, claim_has_support, retrieve_context


# ─────────────────────────────────────────────────────────────────────────────
# Constants — same defaults as codequality.py
# ─────────────────────────────────────────────────────────────────────────────

NVIDIA_API_URL = "https://integrate.api.nvidia.com/v1/chat/completions"
DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"
MIN_CONFIDENCE = 0.7


# ─────────────────────────────────────────────────────────────────────────────
# Helpers — identical logic to codequality.py, kept local to avoid
# cross-module coupling. DRY principle is intentionally relaxed here so
# each agent file is self-contained and independently testable.
# ─────────────────────────────────────────────────────────────────────────────

def _extract_file_diff(
    diff_text: str, filename: str
) -> Tuple[str, List[int], List[Tuple[int, str]]]:
    """
    Extract the diff section for *filename* from a full unified diff.

    Returns:
        (file_diff_text, added_line_numbers, added_lines)
        - file_diff_text:      the raw diff lines for this file
        - added_line_numbers:  sorted list of new-file line numbers that were added
        - added_lines:         list of (line_no, code) pairs for each added line
    """
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
            current_file = line[len("+++ b/"):]
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
    """Strip accidental markdown code fences from LLM output."""
    text = content.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    return text.strip()


def _parse_model_json(content: str) -> List[Dict[str, Any]]:
    """
    Parse JSON from LLM response.  Falls back to bracket-extraction on
    decode failure so a single stray character doesn't drop all findings.
    """
    text = _clean_json_content(content)

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        start = text.find("[")
        end = text.rfind("]")
        if start == -1 or end == -1 or end < start:
            return []
        try:
            data = json.loads(text[start: end + 1])
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
    """Enforce the structured body format so comments are consistent."""
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
    """
    Filter and normalise raw LLM output:
    - Only keep items typed "performance"
    - Enforce MIN_CONFIDENCE threshold
    - Validate line numbers against the actual diff
    - Deduplicate on (type, file, line, body)
    """
    final_results: List[Dict[str, Any]] = []
    seen: Set[tuple] = set()
    valid_line_set = set(valid_lines)

    for item in raw_results:
        # This agent only accepts "performance" findings
        issue_type = item.get("type")
        if issue_type != "performance":
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

        output = {
            "agent": "performance",
            "type": issue_type,
            "file": filename,
            "line": raw_line,
            "body": body,
            "confidence": confidence,
        }

        dedupe_key = (output["type"], output["file"], output["line"], output["body"])
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        final_results.append(output)

    return final_results


# ─────────────────────────────────────────────────────────────────────────────
# Prompt Builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_prompt(
    filename: str,
    commit_sha: Optional[str],
    file_diff: str,
    added_lines: List[Tuple[int, str]],
    valid_lines: List[int],
) -> List[Dict[str, str]]:
    """
    Build the system + user messages for the performance review LLM call.

    System prompt focuses ONLY on performance — never security or quality.
    User prompt lists added lines with their numbers so the model can anchor
    findings to exact, verifiable line positions.
    """
    line_catalog = "\n".join(
        f"{line_no}: {code[:200]}" for line_no, code in added_lines[:400]
    )
    valid_line_json = json.dumps(valid_lines)

    system_prompt = (
        "You are a pull request review agent focused ONLY on performance issues. "
        "Never report security issues. Never report code quality or style issues. "
        "Return strictly valid JSON list and nothing else."
    )

    user_prompt = (
        f"Target file: {filename}\n"
        f"Commit SHA: {commit_sha or ''}\n\n"
        "Analyze ONLY performance issues such as:\n"
        "- Unnecessary loops or O(n²) where O(n) is possible\n"
        "- Repeated lookups in lists where a set or dict would be O(1)\n"
        "- Redundant computations inside loops (precompute outside)\n"
        "- Blocking I/O operations (synchronous DB calls, file reads in hot paths)\n"
        "- Memory-inefficient patterns (building huge intermediate lists, no generators)\n"
        "- Sorting inside loops\n"
        "- String concatenation in loops (use join)\n\n"
        "Do not analyze:\n"
        "- Security issues\n"
        "- Code style or naming\n"
        "- Architecture issues\n\n"
        "Rules:\n"
        "1. Use only these line numbers for comments: "
        f"{valid_line_json}\n"
        "2. Return only high-confidence issues (confidence >= 0.7).\n"
        "3. Keep output minimal and actionable.\n"
        "4. Output must be a JSON list with objects using exactly these keys:\n"
        '   ["agent","type","file","line","body","confidence"]\n'
        '5. agent must be "performance".\n'
        '6. type must be "performance".\n'
        f'7. file must be exactly "{filename}".\n'
        "8. body format must be exactly:\n"
        "   ⚠️ <issue title>\\n\\nExplanation: ...\\n\\nSuggestion: ...\n"
        "9. confidence must be a number from 0.0 to 1.0.\n"
        "10. If no high-confidence performance issue exists, return [] exactly.\n\n"
        "Added lines (line: code):\n"
        f"{line_catalog}\n\n"
        "Unified diff for target file:\n"
        f"{file_diff}"
    )

    return [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]


# ─────────────────────────────────────────────────────────────────────────────
# PerformanceAgent
# ─────────────────────────────────────────────────────────────────────────────

class PerformanceAgent:
    """
    LLM-powered performance analysis agent.

    Takes the same inputs as CodeQualityAgent (raw diff text + filename)
    and returns a list of structured findings in the same format.

    Reuses the NVIDIA LLM endpoint configured via NVIDIA_API_KEY /
    NVIDIA_MODEL environment variables — no new dependencies.
    """

    @staticmethod
    def analyze(
        diff: str, filename: str, commit_sha: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Run performance analysis on the added lines of *filename* in *diff*.

        Args:
            diff:       Raw unified diff text (full PR diff, not just one file).
            filename:   Repo-relative file path to analyse (e.g. "src/utils.py").
            commit_sha: Optional commit SHA for prompt context.

        Returns:
            List of normalised finding dicts, or [] on any failure.
        """
        if not diff or not filename:
            return []

        # Fail silently if API key is missing — don't crash the pipeline
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
        grounded_prompt, retrieved_chunks = augment_prompt_with_context(
            messages[1]["content"],
            query=f"{filename}\n{file_diff}",
            file_hint=filename,
            top_k=6,
        )
        messages[1]["content"] = grounded_prompt

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
            # Network / API error — return empty rather than crashing the pipeline
            return []

        content = (
            response_json.get("choices", [{}])[0]
            .get("message", {})
            .get("content", "")
        )
        if not isinstance(content, str) or not content.strip():
            return []

        raw_results = _parse_model_json(content)
        normalized_results = _validate_and_normalize_results(raw_results, filename, valid_lines)
        if not normalized_results:
            return []

        if not retrieved_chunks:
            retrieved_chunks = retrieve_context(f"{filename}\n{file_diff}", file_hint=filename, top_k=6)
        evidence_texts = [file_diff, *[chunk.content for chunk in retrieved_chunks]]

        grounded_results: List[Dict[str, Any]] = []
        for item in normalized_results:
            if claim_has_support(item.get("body", ""), evidence_texts):
                grounded_results.append(item)
        return grounded_results

    @staticmethod
    def scan(
        diff: str, filename: str, commit_sha: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Alias for analyze() — matches the .scan() interface on CodeQualityAgent."""
        return PerformanceAgent.analyze(diff=diff, filename=filename, commit_sha=commit_sha)


# ─────────────────────────────────────────────────────────────────────────────
# Module-level function alias — matches analyze_code_quality() in codequality.py
# ─────────────────────────────────────────────────────────────────────────────

def analyze_performance(
    diff: str, filename: str, commit_sha: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Convenience wrapper — same signature as analyze_code_quality().

    Returns a list of performance findings for *filename* in *diff*,
    or [] if the agent fails or the API key is not set.
    """
    return PerformanceAgent.analyze(diff=diff, filename=filename, commit_sha=commit_sha)
