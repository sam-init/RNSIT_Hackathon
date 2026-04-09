"""
Lightweight local RAG helpers for grounding LLM prompts and filtering findings.
"""

from .grounding import (
    RAG_ENABLED,
    RetrievedChunk,
    augment_prompt_with_context,
    claim_has_support,
    infer_file_hint,
    retrieve_context,
)

__all__ = [
    "RAG_ENABLED",
    "RetrievedChunk",
    "augment_prompt_with_context",
    "claim_has_support",
    "infer_file_hint",
    "retrieve_context",
]

