#!/usr/bin/env python3
"""
ph - Codebase Health Score & AI Assistant

Core analysis modules (M-01 to M-08) with weighted health scoring.
AI features (ask, review, brief, chat, fix) powered by MegaLLM backend.
"""

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

import requests
import yaml

# ------------------------------------------------------------
# Configuration & Constants
# ------------------------------------------------------------

CACHE_DIR = Path(".ph-cache")
CACHE_DIR.mkdir(exist_ok=True)

# Default LLM endpoint (NVIDIA API). Override via env PH_LLM_ENDPOINT.
DEFAULT_LLM_ENDPOINT = "https://integrate.api.nvidia.com/v1/chat/completions"
LLM_API_KEY = os.getenv("LLM_API_KEY")  # Optional, can be empty for local models
LLM_ENDPOINT = os.getenv("PH_LLM_ENDPOINT", DEFAULT_LLM_ENDPOINT)
LLM_MODEL = os.getenv("PH_LLM_MODEL", "meta/llama-3.1-8b-instruct")

# Health score thresholds
SCORE_EXCELLENT = (90, 100)
SCORE_GOOD = (75, 89)
SCORE_MODERATE = (60, 74)
SCORE_HIGH_RISK = (40, 59)
SCORE_CRITICAL = (0, 39)

MODULE_WEIGHTS = {
    "M-05": 0.20,  # Dependency Security
    "M-02": 0.18,  # Code Quality
    "M-01": 0.15,  # CI/CD Pipeline
    "M-04": 0.14,  # Test Flakiness
    "M-07": 0.13,  # Env Integrity
    "M-08": 0.10,  # Build Performance
    "M-03": 0.06,  # Docs Freshness
    "M-06": 0.04,  # PR Complexity
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("ph")


# ------------------------------------------------------------
# Helper Utilities
# ------------------------------------------------------------

def cache_key(data: Any) -> str:
    """Generate a cache key from any hashable data."""
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def cached(func):
    """Decorator to cache function results in .ph-cache/."""
    def wrapper(*args, **kwargs):
        # Create a key from function name and arguments
        key_data = {"func": func.__name__, "args": args, "kwargs": kwargs}
        key = cache_key(key_data)
        cache_file = CACHE_DIR / f"{key}.json"
        if cache_file.exists():
            with open(cache_file, "r") as f:
                logger.debug(f"Cache hit for {func.__name__}")
                return json.load(f)
        result = func(*args, **kwargs)
        with open(cache_file, "w") as f:
            json.dump(result, f, default=str)
        return result
    return wrapper


def run_cmd(cmd: List[str], cwd: Optional[Path] = None) -> Tuple[str, str, int]:
    """Run a shell command, return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd or Path.cwd(),
            capture_output=True,
            text=True,
            check=False
        )
        return proc.stdout, proc.stderr, proc.returncode
    except Exception as e:
        return "", str(e), -1


# ------------------------------------------------------------
# LLM Client (MegaLLM)
# ------------------------------------------------------------

class MegaLLM:
    """Pluggable LLM client supporting NVIDIA API or local endpoints."""

    def __init__(self, endpoint: str = LLM_ENDPOINT, api_key: str = LLM_API_KEY, model: str = LLM_MODEL):
        self.endpoint = endpoint
        self.api_key = api_key
        self.model = model
        self.conversation_history = []  # For chat mode

    def _call_api(self, messages: List[Dict]) -> str:
        """Send request to LLM endpoint and return response content."""
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": 0.7,
            "max_tokens": 1024,
        }

        try:
            response = requests.post(self.endpoint, headers=headers, json=payload, timeout=30)
            response.raise_for_status()
            data = response.json()
            return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"LLM API call failed: {e}")
            return f"[Error calling LLM: {e}]"

    def ask(self, prompt: str, context: Optional[str] = None) -> str:
        """Single-turn query with optional grounded context."""
        full_prompt = prompt
        if context:
            full_prompt = f"Context from codebase:\n{context}\n\nQuestion: {prompt}"
        messages = [{"role": "user", "content": full_prompt}]
        return self._call_api(messages)

    def review(self, diff: str, test_coverage: Optional[str] = None) -> str:
        """Review a pull request diff with optional coverage data."""
        prompt = f"""
You are a senior code reviewer. Review the following git diff.
Highlight bugs, security gaps, untested paths, and complexity spikes.
Test coverage info (if available): {test_coverage or 'Not provided'}

Diff:
{diff}
"""
        return self.ask(prompt)

    def brief(self, repo_info: Dict) -> str:
        """Generate onboarding brief."""
        prompt = f"""
Generate an ONBOARDING.md for the repository based on this analysis:
- Architecture: {repo_info.get('architecture', 'Unknown')}
- Entry points: {repo_info.get('entry_points', [])}
- Ownership map: {repo_info.get('owners', {})}
- Tech stack: {repo_info.get('tech_stack', [])}
- Health score: {repo_info.get('health_score', 'N/A')}
Write concise, actionable sections.
"""
        return self.ask(prompt)

    def chat(self, user_input: str) -> str:
        """Persistent chat with history."""
        self.conversation_history.append({"role": "user", "content": user_input})
        response = self._call_api(self.conversation_history)
        self.conversation_history.append({"role": "assistant", "content": response})
        return response

    def generate_fix(self, finding: Dict, code_snippet: str) -> str:
        """Generate a patch for a specific finding."""
        prompt = f"""
Given the following code quality finding and the code snippet, produce a unified diff patch that fixes the issue.
Finding: {finding['description']}
Severity: {finding.get('severity', 'medium')}
File: {finding.get('file', 'unknown')}
Line: {finding.get('line', 'N/A')}

Code snippet:
{code_snippet}
"""
        return self.ask(prompt)


if __name__ == "__main__":
    llm = MegaLLM()

    print("AI Assistant Ready! Type 'exit' to quit.\n")

    while True:
        user_input = input("You: ")

        if user_input.lower() == "exit":
            print("Exiting...")
            break

        response = llm.ask(user_input)
        print("\nAI:", response, "\n")