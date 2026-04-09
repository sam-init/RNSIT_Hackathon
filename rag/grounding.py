from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


RAG_ENABLED: bool = _env_bool("PH_RAG_ENABLED", True)
RAG_TOP_K: int = int(os.getenv("PH_RAG_TOP_K", "6"))
RAG_CONTEXT_CHARS: int = int(os.getenv("PH_RAG_CONTEXT_CHARS", "3500"))

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{1,}")
_FILE_HINT_PATTERNS = [
    re.compile(r"(?im)^File:\s*([^\n]+)$"),
    re.compile(r"(?im)^Target file:\s*([^\n]+)$"),
    re.compile(r"(?im)^path:\s*([^\n]+)$"),
]
_STOPWORDS: Set[str] = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "if", "in", "is",
    "it", "of", "on", "or", "that", "the", "this", "to", "with", "when", "where",
    "into", "only", "must", "should", "would", "could", "can", "not", "no", "yes",
}


@dataclass(frozen=True)
class RetrievedChunk:
    source: str
    start_line: int
    end_line: int
    content: str
    score: float


@dataclass
class _IndexedChunk:
    source: str
    start_line: int
    end_line: int
    content: str
    terms: Set[str]


class LocalRAGRetriever:
    INCLUDE_SUFFIXES: Set[str] = {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rs", ".rb", ".php",
        ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".swift", ".kt", ".scala",
        ".sql", ".sh", ".bash", ".zsh", ".yml", ".yaml", ".toml", ".ini", ".cfg",
        ".conf", ".json", ".md", ".txt", ".rst", ".html", ".css", ".xml",
    }
    SKIP_DIRS: Set[str] = {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv",
        ".mypy_cache", ".pytest_cache", ".ph-cache", ".idea", ".vscode",
    }

    def __init__(
        self,
        repo_root: Optional[Path] = None,
        chunk_lines: int = 60,
        overlap_lines: int = 15,
        max_file_bytes: int = 250_000,
    ) -> None:
        self.repo_root = (repo_root or Path.cwd()).resolve()
        self.chunk_lines = max(10, chunk_lines)
        self.overlap_lines = max(0, min(overlap_lines, self.chunk_lines - 1))
        self.max_file_bytes = max_file_bytes
        self._lock = threading.Lock()
        self._fingerprint: Optional[Tuple[Tuple[str, int, int], ...]] = None
        self._chunks: List[_IndexedChunk] = []

    def _should_index(self, path: Path) -> bool:
        if not path.is_file():
            return False
        if path.name.startswith(".") and path.suffix.lower() not in {".env.example"}:
            return False
        if path.suffix and path.suffix.lower() not in self.INCLUDE_SUFFIXES:
            return False
        try:
            if path.stat().st_size > self.max_file_bytes:
                return False
        except OSError:
            return False
        return True

    def _iter_files(self) -> List[Path]:
        files: List[Path] = []
        for root, dirs, filenames in os.walk(self.repo_root):
            dirs[:] = [d for d in dirs if d not in self.SKIP_DIRS]
            root_path = Path(root)
            for filename in filenames:
                candidate = root_path / filename
                if self._should_index(candidate):
                    files.append(candidate)
        return sorted(files)

    def _build_fingerprint(self, files: Sequence[Path]) -> Tuple[Tuple[str, int, int], ...]:
        fingerprint: List[Tuple[str, int, int]] = []
        for path in files:
            try:
                stat = path.stat()
            except OSError:
                continue
            rel = path.relative_to(self.repo_root).as_posix()
            fingerprint.append((rel, stat.st_mtime_ns, stat.st_size))
        return tuple(fingerprint)

    @staticmethod
    def _tokenize(text: str) -> Set[str]:
        return {t.lower() for t in _TOKEN_RE.findall(text) if t.lower() not in _STOPWORDS}

    def _chunk_file(self, path: Path) -> List[_IndexedChunk]:
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return []
        lines = text.splitlines()
        if not lines:
            return []

        rel = path.relative_to(self.repo_root).as_posix()
        step = max(1, self.chunk_lines - self.overlap_lines)
        chunks: List[_IndexedChunk] = []
        start = 1
        while start <= len(lines):
            end = min(len(lines), start + self.chunk_lines - 1)
            body = "\n".join(lines[start - 1:end]).strip()
            if body:
                terms = self._tokenize(body)
                if terms:
                    chunks.append(
                        _IndexedChunk(
                            source=rel,
                            start_line=start,
                            end_line=end,
                            content=body,
                            terms=terms,
                        )
                    )
            start += step
        return chunks

    def refresh(self) -> None:
        files = self._iter_files()
        new_fingerprint = self._build_fingerprint(files)
        with self._lock:
            if new_fingerprint == self._fingerprint:
                return

            new_chunks: List[_IndexedChunk] = []
            for path in files:
                new_chunks.extend(self._chunk_file(path))

            self._chunks = new_chunks
            self._fingerprint = new_fingerprint

    def retrieve(self, query: str, file_hint: Optional[str] = None, top_k: int = RAG_TOP_K) -> List[RetrievedChunk]:
        if not RAG_ENABLED:
            return []
        clean_query = query.strip()
        if not clean_query:
            return []
        self.refresh()
        query_terms = self._tokenize(clean_query)
        if not query_terms:
            return []

        hint = (file_hint or "").strip().replace("\\", "/")
        ranked: List[RetrievedChunk] = []
        for chunk in self._chunks:
            overlap = query_terms.intersection(chunk.terms)
            if not overlap:
                continue
            # Lightweight lexical scoring with a small path bonus.
            score = len(overlap) / max(len(query_terms), 1)
            if hint and (chunk.source == hint or chunk.source.endswith(hint)):
                score += 0.25
            ranked.append(
                RetrievedChunk(
                    source=chunk.source,
                    start_line=chunk.start_line,
                    end_line=chunk.end_line,
                    content=chunk.content,
                    score=score,
                )
            )

        ranked.sort(key=lambda c: c.score, reverse=True)
        return ranked[: max(1, top_k)]


_SHARED_RETRIEVER = LocalRAGRetriever()


def retrieve_context(query: str, file_hint: Optional[str] = None, top_k: int = RAG_TOP_K) -> List[RetrievedChunk]:
    return _SHARED_RETRIEVER.retrieve(query=query, file_hint=file_hint, top_k=top_k)


def infer_file_hint(text: str) -> Optional[str]:
    for pattern in _FILE_HINT_PATTERNS:
        match = pattern.search(text)
        if match:
            return match.group(1).strip()
    return None


def _render_chunks(chunks: Sequence[RetrievedChunk], max_chars: int = RAG_CONTEXT_CHARS) -> str:
    if not chunks:
        return ""

    parts: List[str] = []
    used = 0
    for chunk in chunks:
        header = (
            f"[source={chunk.source} lines={chunk.start_line}-{chunk.end_line} "
            f"score={chunk.score:.3f}]"
        )
        body = chunk.content.strip()
        block = f"{header}\n{body}\n"
        if used + len(block) > max_chars:
            break
        parts.append(block)
        used += len(block)
    return "\n".join(parts).strip()


def augment_prompt_with_context(
    prompt: str,
    query: Optional[str] = None,
    file_hint: Optional[str] = None,
    top_k: int = RAG_TOP_K,
    max_chars: int = RAG_CONTEXT_CHARS,
) -> Tuple[str, List[RetrievedChunk]]:
    if not RAG_ENABLED:
        return prompt, []
    if "<retrieved_context>" in prompt:
        return prompt, []

    effective_query = (query or prompt).strip()
    chunks = retrieve_context(effective_query, file_hint=file_hint, top_k=top_k)
    if not chunks:
        return prompt, []

    context_block = _render_chunks(chunks, max_chars=max_chars)
    if not context_block:
        return prompt, []

    grounded_prompt = (
        f"{prompt}\n\n"
        "<retrieved_context>\n"
        f"{context_block}\n"
        "</retrieved_context>\n\n"
        "<grounding_rules>\n"
        "- Use retrieved context as evidence.\n"
        "- If evidence is insufficient, do not speculate.\n"
        "- For JSON review tasks, return [] when uncertain.\n"
        "</grounding_rules>"
    )
    return grounded_prompt, chunks


def claim_has_support(
    claim_text: str,
    evidence_texts: Sequence[str],
    min_overlap_terms: int = 2,
    min_overlap_ratio: float = 0.12,
) -> bool:
    claim_terms = LocalRAGRetriever._tokenize(claim_text)
    if not claim_terms:
        return False

    for evidence in evidence_texts:
        evidence_terms = LocalRAGRetriever._tokenize(evidence)
        if not evidence_terms:
            continue
        overlap = claim_terms.intersection(evidence_terms)
        if len(overlap) < min_overlap_terms:
            continue
        ratio = len(overlap) / max(len(claim_terms), 1)
        if ratio >= min_overlap_ratio:
            return True
    return False

