#!/usr/bin/env python3
"""
ph - Codebase Health Score & AI Assistant

Advanced version with:
- Async HTTP client (httpx) for non‑blocking LLM calls
- Retry & circuit breaker patterns (tenacity)
- Structured logging & metrics hooks
- Configurable prompt templates
- Conversation memory with token limit awareness
- Streaming support (optional)
- Pydantic settings for robust configuration
- Caching with TTL and disk fallback
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Callable, Awaitable
from functools import wraps

import yaml
import httpx
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    RetryError
)
from pydantic import BaseSettings, Field, validator

# ------------------------------------------------------------
# Configuration using Pydantic (env aware)
# ------------------------------------------------------------

class LLMSettings(BaseSettings):
    """LLM configuration loaded from environment variables."""
    endpoint: str = Field(
        "https://integrate.api.nvidia.com/v1/chat/completions",
        env="PH_LLM_ENDPOINT"
    )
    api_key: Optional[str] = Field(None, env="LLM_API_KEY")
    model: str = Field("meta/llama-3.1-8b-instruct", env="PH_LLM_MODEL")
    temperature: float = Field(0.7, env="PH_LLM_TEMPERATURE")
    max_tokens: int = Field(1024, env="PH_LLM_MAX_TOKENS")
    timeout_seconds: float = Field(30.0, env="PH_LLM_TIMEOUT")
    max_retries: int = Field(3, env="PH_LLM_MAX_RETRIES")
    
    class Config:
        env_file = ".env"
        case_sensitive = False

class CacheSettings(BaseSettings):
    """Cache configuration."""
    ttl_seconds: int = Field(3600, env="PH_CACHE_TTL")
    cache_dir: Path = Field(Path(".ph-cache"), env="PH_CACHE_DIR")
    
    class Config:
        env_file = ".env"

# Global settings instances
llm_settings = LLMSettings()
cache_settings = CacheSettings()

# ------------------------------------------------------------
# Logging setup
# ------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("ph.ai_agent")

# ------------------------------------------------------------
# Async caching with TTL
# ------------------------------------------------------------

class AsyncTTLCache:
    """Simple async TTL cache using dict with expiration."""
    def __init__(self, default_ttl_seconds: int = 3600):
        self._store: Dict[str, Tuple[Any, float]] = {}
        self._default_ttl = default_ttl_seconds
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value if not expired."""
        if key in self._store:
            value, expires_at = self._store[key]
            if asyncio.get_event_loop().time() < expires_at:
                return value
            else:
                del self._store[key]
        return None
    
    async def set(self, key: str, value: Any, ttl_seconds: Optional[int] = None):
        """Store value with TTL."""
        ttl = ttl_seconds or self._default_ttl
        expires_at = asyncio.get_event_loop().time() + ttl
        self._store[key] = (value, expires_at)
    
    async def clear(self):
        self._store.clear()

# Global cache instance
_response_cache = AsyncTTLCache(default_ttl_seconds=cache_settings.ttl_seconds)

def async_cache(ttl_seconds: Optional[int] = None):
    """Decorator to cache async function results with TTL."""
    def decorator(func: Callable[..., Awaitable[Any]]):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Build cache key from function name and arguments
            key_data = {"func": func.__name__, "args": args, "kwargs": kwargs}
            key = hashlib.sha256(json.dumps(key_data, sort_keys=True).encode()).hexdigest()
            cached = await _response_cache.get(key)
            if cached is not None:
                logger.debug(f"Cache hit for {func.__name__}")
                return cached
            result = await func(*args, **kwargs)
            await _response_cache.set(key, result, ttl_seconds)
            return result
        return wrapper
    return decorator

# ------------------------------------------------------------
# Async LLM Client (MegaLLM) with retries & streaming
# ------------------------------------------------------------

class MegaLLM:
    """
    Advanced LLM client supporting:
    - Async HTTP requests (httpx)
    - Automatic retries with exponential backoff
    - Conversation history management
    - Optional streaming responses
    - Configurable prompt templates
    """
    
    def __init__(self, settings: Optional[LLMSettings] = None):
        self.settings = settings or llm_settings
        self.conversation_history: List[Dict[str, str]] = []
        self._client: Optional[httpx.AsyncClient] = None
    
    async def _get_client(self) -> httpx.AsyncClient:
        """Lazily initialize HTTP client with connection pooling."""
        if self._client is None:
            self._client = httpx.AsyncClient(
                timeout=self.settings.timeout_seconds,
                limits=httpx.Limits(max_keepalive_connections=20, max_connections=100)
            )
        return self._client
    
    async def close(self):
        """Clean up HTTP client."""
        if self._client:
            await self._client.aclose()
            self._client = None
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TimeoutException))
    )
    async def _call_api(self, messages: List[Dict[str, str]]) -> str:
        """
        Send request to LLM endpoint with retry logic.
        Returns the assistant's message content.
        """
        headers = {"Content-Type": "application/json"}
        if self.settings.api_key:
            headers["Authorization"] = f"Bearer {self.settings.api_key}"
        
        payload = {
            "model": self.settings.model,
            "messages": messages,
            "temperature": self.settings.temperature,
            "max_tokens": self.settings.max_tokens,
            "stream": False,  # Streaming can be enabled separately
        }
        
        client = await self._get_client()
        response = await client.post(
            self.settings.endpoint,
            headers=headers,
            json=payload
        )
        response.raise_for_status()
        data = response.json()
        
        # Extract content - handle various response formats
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as e:
            logger.error(f"Unexpected LLM response format: {data}")
            raise ValueError("Invalid response from LLM") from e
    
    async def ask(self, prompt: str, context: Optional[str] = None) -> str:
        """Single‑turn query with optional grounded context."""
        full_prompt = prompt
        if context:
            full_prompt = f"Context from codebase:\n{context}\n\nQuestion: {prompt}"
        messages = [{"role": "user", "content": full_prompt}]
        try:
            return await self._call_api(messages)
        except RetryError as e:
            logger.error(f"LLM request failed after retries: {e}")
            return f"[Error: LLM unreachable after {self.settings.max_retries} attempts]"
    
    async def review(self, diff: str, test_coverage: Optional[str] = None) -> str:
        """
        Review a pull request diff with optional test coverage info.
        Uses a structured prompt for high‑quality reviews.
        """
        prompt = f"""
You are a senior code reviewer. Review the following git diff.
Focus on:
- Potential bugs and logic errors
- Security vulnerabilities (injection, auth, data leaks)
- Performance bottlenecks
- Untested code paths
- Code complexity (cyclomatic, nesting)

Test coverage info (if available): {test_coverage or 'Not provided'}

Diff:
{diff}

Provide a concise, actionable report with bullet points.
If no issues, state "No critical issues found."
"""
        return await self.ask(prompt)
    
    async def brief(self, repo_info: Dict[str, Any]) -> str:
        """Generate an onboarding brief for a repository."""
        prompt = f"""
Generate an ONBOARDING.md for the repository based on this analysis:
- Architecture: {repo_info.get('architecture', 'Unknown')}
- Entry points: {repo_info.get('entry_points', [])}
- Ownership map: {repo_info.get('owners', {})}
- Tech stack: {repo_info.get('tech_stack', [])}
- Health score: {repo_info.get('health_score', 'N/A')}

Write concise, actionable sections:
1. Quick Start
2. Key Components
3. Contribution Workflow
4. Environment Setup
5. Troubleshooting
"""
        return await self.ask(prompt)
    
    async def chat(self, user_input: str) -> str:
        """
        Persistent chat with conversation history.
        Automatically truncates history if token limit approached (simple heuristic).
        """
        self.conversation_history.append({"role": "user", "content": user_input})
        # Truncate to last 20 messages to avoid token overflow (adjustable)
        if len(self.conversation_history) > 20:
            self.conversation_history = self.conversation_history[-20:]
        response = await self._call_api(self.conversation_history)
        self.conversation_history.append({"role": "assistant", "content": response})
        return response
    
    async def generate_fix(self, finding: Dict[str, Any], code_snippet: str) -> str:
        """
        Generate a unified diff patch to fix a specific code quality finding.
        """
        prompt = f"""
Given the following code quality finding and the code snippet, produce a unified diff patch that fixes the issue.

Finding: {finding.get('description', 'No description')}
Severity: {finding.get('severity', 'medium')}
File: {finding.get('file', 'unknown')}
Line: {finding.get('line', 'N/A')}

Code snippet:
```python
{code_snippet}