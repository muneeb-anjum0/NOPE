from __future__ import annotations

import asyncio
import hashlib
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable
from uuid import UUID

import httpx
from pydantic import BaseModel, Field

from nope_api.config import Settings
from nope_api.embeddings import (
    EmbeddingCompatibilityError,
    embedding_provider,
    run_embedding_call,
)
from nope_api.models import Finding, Scan, new_id
from nope_api.rag import RagChunk, RagContext, rag_limits, redact_text


INDEX_SCHEMA_VERSION = "repo-intelligence.v1"
CHUNKER_VERSION = "stage14-chunker-v1"
RAG_VERSION = "stage14-hybrid-rag-v1"
QDRANT_COLLECTION = "nope_repository_chunks_v1"


def qdrant_point_id(chunk_id: str) -> str:
    """Map NOPE chunk identifiers to Qdrant's UUID-compatible point IDs."""
    return str(UUID(stable_hash(chunk_id)[:32]))


class RepositoryIndexCancelled(RuntimeError):
    """Raised when repository-intelligence indexing is cancelled cleanly."""

SOURCE_SUFFIXES = {
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".py",
    ".json",
    ".yaml",
    ".yml",
    ".sql",
    ".md",
    ".sh",
    ".bash",
    ".dockerfile",
    ".tf",
    ".toml",
    ".map",
    ".rules",
}
SPECIAL_FILENAMES = {"Dockerfile", ".env", "firebase.rules", "docker-compose.yml", "package.json", "package-lock.json", "requirements.txt", "pyproject.toml"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".turbo",
    ".pytest_cache",
    ".mypy_cache",
    "__pycache__",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "coverage",
    "target",
    ".venv",
    "venv",
    ".nope-workspaces",
    "models",
    "qdrant_storage",
    "minio",
}
BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar", ".exe", ".dll", ".so", ".dylib", ".gguf"}

SYMBOL_RE = re.compile(
    r"(?:(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)|"
    r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^)]*\)\s*=>|"
    r"(?:export\s+)?class\s+([A-Za-z_$][\w$]*)|"
    r"(?:async\s+)?def\s+([A-Za-z_][\w]*)\s*\(|"
    r"class\s+([A-Za-z_][\w]*)\s*[:(])"
)
IMPORT_RE = re.compile(r"\b(?:import|require|from)\b[^\n;]*")
ROUTE_RE = re.compile(r"\b(?:GET|POST|PUT|PATCH|DELETE|loader|action|middleware|router\.(?:get|post|put|patch|delete)|app\.(?:get|post|put|patch|delete))\b", re.I)
AUTH_RE = re.compile(r"\b(auth|session|jwt|token|owner|tenant|user_id|organization_id|policy|rls|permission|authorize|requireUser)\b", re.I)
DATA_RE = re.compile(r"\b(prisma\.|supabase\.|select\(|findUnique|findFirst|insert\(|update\(|delete\(|from\(|storage\.|bucket)\b", re.I)
AI_RE = re.compile(r"\b(openai|anthropic|qwen|llama|prompt|completion|embedding|rag|token|model)\b", re.I)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def stable_hash(value: str | bytes) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8", errors="ignore")
    return hashlib.sha256(raw).hexdigest()


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def language_for(path: Path) -> str:
    name = path.name
    suffix = path.suffix.lower()
    if name == "Dockerfile" or suffix == ".dockerfile":
        return "dockerfile"
    return {
        ".js": "javascript",
        ".jsx": "jsx",
        ".ts": "typescript",
        ".tsx": "tsx",
        ".py": "python",
        ".json": "json",
        ".yaml": "yaml",
        ".yml": "yaml",
        ".sql": "sql",
        ".md": "markdown",
        ".sh": "shell",
        ".bash": "shell",
        ".tf": "terraform",
        ".toml": "toml",
    }.get(suffix, "text")


def framework_hints(rel: str, text: str) -> list[str]:
    lowered = f"{rel}\n{text[:4000]}".lower()
    hints = []
    for key, markers in {
        "nextjs": ["app/api/", "pages/api/", "route.ts", "next/"],
        "sveltekit": ["src/routes/", "+page.svelte", "+server.ts"],
        "express": ["express", "router.get", "app.get"],
        "fastapi": ["fastapi", "@app.get", "apirouter"],
        "supabase": ["supabase", "row level security", "auth.uid()"],
        "prisma": ["prisma.", "schema.prisma"],
        "docker": ["dockerfile", "docker-compose"],
    }.items():
        if any(marker in lowered for marker in markers):
            hints.append(key)
    return sorted(set(hints))


def route_metadata(rel: str, text: str) -> dict[str, Any]:
    route = None
    if "app/api/" in rel:
        route = "/" + rel.split("app/api/", 1)[1].rsplit("/", 1)[0]
        route = route.replace("[", ":").replace("]", "")
    elif "pages/api/" in rel:
        route = "/" + rel.split("pages/api/", 1)[1].rsplit(".", 1)[0]
        route = route.replace("[", ":").replace("]", "")
    elif "src/routes/" in rel:
        route = "/" + rel.split("src/routes/", 1)[1].rsplit("/", 1)[0]
    methods = sorted(set(match.group(0).upper() for match in re.finditer(r"\b(GET|POST|PUT|PATCH|DELETE)\b", text)))
    return {"route": route, "methods": methods}


@dataclass
class RepositoryFile:
    path: Path
    rel: str
    language: str
    text: str
    file_hash: str
    framework_hints: list[str]
    imports: list[str]


class IndexedChunk(BaseModel):
    id: str
    project_id: str | None = None
    scan_id: str
    relative_path: str
    language: str
    framework_hints: list[str] = Field(default_factory=list)
    symbol_name: str | None = None
    symbol_type: str = "module"
    start_line: int = 1
    end_line: int = 1
    parent_symbol: str | None = None
    imports: list[str] = Field(default_factory=list)
    exported: bool = False
    route_metadata: dict[str, Any] = Field(default_factory=dict)
    auth_relevance: bool = False
    data_access_relevance: bool = False
    storage_relevance: bool = False
    ai_relevance: bool = False
    rule_evidence_refs: list[str] = Field(default_factory=list)
    content_hash: str
    file_hash: str
    chunker_version: str = CHUNKER_VERSION
    index_schema_version: str = INDEX_SCHEMA_VERSION
    token_estimate: int = 1
    text: str


class RetrievalResult(BaseModel):
    chunk_id: str
    relative_path: str
    language: str
    symbol_name: str | None = None
    symbol_type: str = "module"
    start_line: int
    end_line: int
    text: str
    sources: list[str]
    score: float
    score_reasons: dict[str, float]
    retrieval_reason: str
    trust_boundary: str = "untrusted_repository_data"
    metadata: dict[str, Any] = Field(default_factory=dict)


class SearchResponse(BaseModel):
    query: str
    scan_id: str
    project_id: str | None = None
    results: list[RetrievalResult]
    diagnostics: dict[str, Any] = Field(default_factory=dict)


class IndexResult(BaseModel):
    index_id: str
    scan_id: str
    project_id: str | None = None
    status: str
    files_discovered: int = 0
    files_indexed: int = 0
    files_skipped: int = 0
    chunks_generated: int = 0
    chunks_embedded: int = 0
    vectors_added: int = 0
    vectors_reused: int = 0
    vectors_deleted: int = 0
    duration_ms: int = 0
    embedding_model: str
    embedding_provider: str
    embedding_dimension: int
    distance_metric: str = "Cosine"
    chunker_version: str = CHUNKER_VERSION
    index_schema_version: str = INDEX_SCHEMA_VERSION
    errors: list[str] = Field(default_factory=list)


class VectorStore:
    def __init__(self, settings: Settings, dimension: int):
        self.settings = settings
        self.dimension = dimension
        self.url = settings.qdrant_url.rstrip("/")

    async def health(self) -> dict[str, Any]:
        if self.settings.vector_store != "qdrant":
            return {"status": "disabled", "store": self.settings.vector_store}
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                response = await client.get(f"{self.url}/")
                response.raise_for_status()
            return {"status": "ok", "store": "qdrant", "url": self.url, "collection": QDRANT_COLLECTION}
        except Exception as exc:
            return {"status": "failed", "store": "qdrant", "message": str(exc)}

    async def ensure_collection(self) -> None:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{self.url}/collections/{QDRANT_COLLECTION}")
            if response.status_code == 200:
                data = response.json().get("result", {})
                vectors = data.get("config", {}).get("params", {}).get("vectors", {})
                size = vectors.get("size") if isinstance(vectors, dict) else None
                if size is not None and int(size) != int(self.dimension):
                    raise EmbeddingCompatibilityError(
                        f"Qdrant collection {QDRANT_COLLECTION} has dimension {size}, but the configured embedding model uses {self.dimension}. Recreate the repository index after clearing the old vector collection."
                    )
                return
            payload = {"vectors": {"size": self.dimension, "distance": "Cosine"}, "optimizers_config": {"default_segment_number": 2}}
            response = await client.put(f"{self.url}/collections/{QDRANT_COLLECTION}", json=payload)
            response.raise_for_status()

    async def upsert(self, chunks: list[IndexedChunk], vectors: list[list[float]]) -> None:
        if not chunks:
            return
        points = []
        for chunk, vector in zip(chunks, vectors):
            points.append(
                {
                    "id": qdrant_point_id(chunk.id),
                    "vector": vector,
                    "payload": {
                        "chunk_id": chunk.id,
                        "scan_id": chunk.scan_id,
                        "project_id": chunk.project_id,
                        "relative_path": chunk.relative_path,
                        "language": chunk.language,
                        "symbol_name": chunk.symbol_name,
                        "symbol_type": chunk.symbol_type,
                        "start_line": chunk.start_line,
                        "end_line": chunk.end_line,
                        "content_hash": chunk.content_hash,
                        "chunker_version": chunk.chunker_version,
                        "index_schema_version": chunk.index_schema_version,
                    },
                }
            )
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.put(f"{self.url}/collections/{QDRANT_COLLECTION}/points?wait=true", json={"points": points})
            response.raise_for_status()

    async def search(self, query_vector: list[float], *, owner_filter: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        filters = [{"key": key, "match": {"value": value}} for key, value in owner_filter.items() if value is not None]
        payload = {"vector": query_vector, "limit": limit, "with_payload": True, "filter": {"must": filters}}
        async with httpx.AsyncClient(timeout=self.settings.retrieval_query_timeout_seconds) as client:
            response = await client.post(f"{self.url}/collections/{QDRANT_COLLECTION}/points/search", json=payload)
            response.raise_for_status()
        return response.json().get("result", [])

    async def delete_scan(self, scan_id: str) -> None:
        payload = {"filter": {"must": [{"key": "scan_id", "match": {"value": scan_id}}]}}
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.post(f"{self.url}/collections/{QDRANT_COLLECTION}/points/delete?wait=true", json=payload)
            if response.status_code not in {200, 404}:
                response.raise_for_status()


async def delete_repository_vectors(settings: Settings, scan_ids: list[str]) -> None:
    """Delete external vector data before the relational scan records disappear."""
    if settings.vector_store != "qdrant" or not scan_ids:
        return
    vector_store = VectorStore(settings, dimension=1)
    for scan_id in scan_ids:
        await vector_store.delete_scan(scan_id)


def should_index(path: Path, root: Path, settings: Settings) -> tuple[bool, str | None]:
    rel = path.relative_to(root)
    parts = set(rel.parts)
    if parts & SKIP_DIRS:
        return False, "excluded directory"
    if path.suffix.lower() in BINARY_SUFFIXES:
        return False, "binary or model file"
    if path.stat().st_size > settings.retrieval_max_file_bytes:
        return False, "file too large"
    if path.suffix.lower() not in SOURCE_SUFFIXES and path.name not in SPECIAL_FILENAMES:
        return False, "unsupported file type"
    return True, None


def _raise_if_cancelled(cancelled: Callable[[], bool] | None) -> None:
    if cancelled and cancelled():
        raise RepositoryIndexCancelled("Repository intelligence indexing was cancelled.")


def read_repository_files(root: Path, settings: Settings, cancelled: Callable[[], bool] | None = None) -> tuple[list[RepositoryFile], dict[str, Any]]:
    files: list[RepositoryFile] = []
    skipped = 0
    total_bytes = 0
    discovered = 0
    for path in root.rglob("*"):
        _raise_if_cancelled(cancelled)
        if not path.is_file():
            continue
        discovered += 1
        if discovered > settings.retrieval_max_file_count:
            skipped += 1
            continue
        ok, _reason = should_index(path, root, settings)
        if not ok:
            skipped += 1
            continue
        raw = path.read_bytes()
        total_bytes += len(raw)
        if total_bytes > settings.retrieval_max_total_bytes:
            skipped += 1
            continue
        text = raw.decode("utf-8", errors="ignore")
        rel = path.relative_to(root).as_posix()
        files.append(
            RepositoryFile(
                path=path,
                rel=rel,
                language=language_for(path),
                text=text,
                file_hash=stable_hash(raw),
                framework_hints=framework_hints(rel, text),
                imports=sorted(set(match.group(0)[:180] for match in IMPORT_RE.finditer(text))),
            )
        )
    return files, {"files_discovered": discovered, "files_skipped": skipped, "total_bytes": total_bytes}


def line_for_index(lines: list[str], index: int) -> int:
    return max(1, min(len(lines) or 1, index + 1))


def semantic_blocks(repo_file: RepositoryFile, settings: Settings, cancelled: Callable[[], bool] | None = None) -> list[tuple[str | None, str, int, int, str]]:
    _raise_if_cancelled(cancelled)
    lines = repo_file.text.splitlines()
    if not lines:
        return []
    blocks: list[tuple[str | None, str, int, int, str]] = []
    matches = list(SYMBOL_RE.finditer(repo_file.text))
    line_offsets = []
    offset = 0
    for line in lines:
        line_offsets.append(offset)
        offset += len(line) + 1
    if matches:
        for idx, match in enumerate(matches):
            _raise_if_cancelled(cancelled)
            symbol = next((group for group in match.groups() if group), None)
            start_line = repo_file.text.count("\n", 0, match.start()) + 1
            next_start = matches[idx + 1].start() if idx + 1 < len(matches) else len(repo_file.text)
            end_line = repo_file.text.count("\n", 0, max(match.start(), next_start - 1)) + 1
            if end_line - start_line > 180:
                end_line = start_line + 180
            text = "\n".join(lines[start_line - 1 : end_line])
            blocks.append((symbol, "symbol", start_line, end_line, text))
    if not blocks:
        if repo_file.language in {"json", "yaml", "toml", "dockerfile", "sql", "markdown", "shell", "terraform"}:
            window = max(20, settings.retrieval_max_chunk_chars // 80)
            for start in range(1, len(lines) + 1, window):
                _raise_if_cancelled(cancelled)
                end = min(len(lines), start + window - 1)
                blocks.append((None, "configuration" if repo_file.language != "markdown" else "section", start, end, "\n".join(lines[start - 1 : end])))
        else:
            blocks.append((None, "module", 1, len(lines), repo_file.text))
    return blocks


def make_chunks(root: Path, scan: Scan, settings: Settings, cancelled: Callable[[], bool] | None = None) -> tuple[list[IndexedChunk], dict[str, Any]]:
    repo_files, stats = read_repository_files(root, settings, cancelled)
    chunks: list[IndexedChunk] = []
    evidence_by_file: dict[str, list[str]] = {}
    for finding in scan.findings:
        if finding.affected_file:
            evidence_by_file.setdefault(finding.affected_file, []).append(finding.id)
        for evidence in finding.evidence:
            if evidence.file:
                evidence_by_file.setdefault(evidence.file, []).append(finding.id)
    for repo_file in repo_files:
        _raise_if_cancelled(cancelled)
        route_meta = route_metadata(repo_file.rel, repo_file.text)
        for symbol, symbol_type, start_line, end_line, text in semantic_blocks(repo_file, settings, cancelled):
            _raise_if_cancelled(cancelled)
            if not text.strip():
                continue
            if len(chunks) >= settings.retrieval_max_chunks:
                stats["chunk_cap_reached"] = True
                break
            trimmed = text[: settings.retrieval_max_chunk_chars]
            content_hash = stable_hash(trimmed)
            chunk_id_seed = f"{scan.project_id}:{repo_file.rel}:{symbol or 'module'}:{start_line}:{end_line}:{content_hash}:{CHUNKER_VERSION}"
            chunks.append(
                IndexedChunk(
                    id="ric_" + stable_hash(chunk_id_seed)[:32],
                    project_id=scan.project_id,
                    scan_id=scan.id,
                    relative_path=repo_file.rel,
                    language=repo_file.language,
                    framework_hints=repo_file.framework_hints,
                    symbol_name=symbol,
                    symbol_type=symbol_type,
                    start_line=start_line,
                    end_line=end_line,
                    imports=repo_file.imports[:20],
                    exported="export " in trimmed[:200],
                    route_metadata=route_meta,
                    auth_relevance=bool(AUTH_RE.search(trimmed)),
                    data_access_relevance=bool(DATA_RE.search(trimmed)),
                    storage_relevance="storage" in trimmed.lower() or "bucket" in trimmed.lower(),
                    ai_relevance=bool(AI_RE.search(trimmed)),
                    rule_evidence_refs=sorted(set(evidence_by_file.get(repo_file.rel, []))),
                    content_hash=content_hash,
                    file_hash=repo_file.file_hash,
                    token_estimate=estimate_tokens(trimmed),
                    text=redact_text(trimmed),
                )
            )
    stats["files_indexed"] = len(repo_files)
    stats["chunks_generated"] = len(chunks)
    return chunks, stats


def keyword_score(query_terms: set[str], chunk: IndexedChunk) -> float:
    haystack = " ".join([chunk.relative_path, chunk.symbol_name or "", chunk.text, " ".join(chunk.framework_hints)]).lower()
    hits = sum(1 for term in query_terms if term and term in haystack)
    return min(1.0, hits / max(1, min(len(query_terms), 8)))


def exact_score(query: str, chunk: IndexedChunk) -> float:
    lowered = query.lower().strip()
    if not lowered:
        return 0.0
    values = [chunk.relative_path.lower(), (chunk.symbol_name or "").lower(), chunk.route_metadata.get("route") or ""]
    if lowered in values:
        return 1.0
    if any(lowered in value for value in values):
        return 0.75
    return 0.0


def graph_score(scan: Scan, chunk: IndexedChunk) -> float:
    if not scan.code_graph.nodes:
        return 0.0
    score = 0.0
    for node in scan.code_graph.nodes:
        if node.file == chunk.relative_path:
            score = max(score, 0.8 if node.risk else 0.45)
        if chunk.symbol_name and chunk.symbol_name.lower() in node.label.lower():
            score = max(score, 0.5)
    return score


def finding_centered_score(findings: list[Finding], chunk: IndexedChunk) -> float:
    score = 0.0
    for finding in findings:
        if finding.affected_file == chunk.relative_path:
            score = max(score, 1.0)
        if finding.symbol and finding.symbol == chunk.symbol_name:
            score = max(score, 0.8)
        if finding.affected_route and finding.affected_route == chunk.route_metadata.get("route"):
            score = max(score, 0.75)
        if finding.id in chunk.rule_evidence_refs:
            score = max(score, 0.9)
    return score


def fuse_scores(scores: dict[str, float]) -> float:
    weights = {"exact": 0.26, "keyword": 0.22, "graph": 0.16, "vector": 0.22, "finding": 0.14}
    return round(sum(min(1.0, max(0.0, scores.get(key, 0.0))) * weight for key, weight in weights.items()), 6)


def result_from_chunk(chunk: IndexedChunk, sources: list[str], scores: dict[str, float]) -> RetrievalResult:
    reason = ", ".join(source for source in sources if scores.get(source, 0) > 0) or "ranked by deterministic hybrid retrieval"
    return RetrievalResult(
        chunk_id=chunk.id,
        relative_path=chunk.relative_path,
        language=chunk.language,
        symbol_name=chunk.symbol_name,
        symbol_type=chunk.symbol_type,
        start_line=chunk.start_line,
        end_line=chunk.end_line,
        text=chunk.text,
        sources=sources,
        score=fuse_scores(scores),
        score_reasons=scores,
        retrieval_reason=reason,
        metadata={
            "framework_hints": chunk.framework_hints,
            "route": chunk.route_metadata.get("route"),
            "auth_relevance": chunk.auth_relevance,
            "data_access_relevance": chunk.data_access_relevance,
            "ai_relevance": chunk.ai_relevance,
            "rule_evidence_refs": chunk.rule_evidence_refs,
        },
    )


def context_from_results(results: list[RetrievalResult], settings: Settings, *, max_chunks: int | None = None) -> RagContext:
    limits = rag_limits(settings)
    if max_chunks:
        limits.max_chunks = max(1, max_chunks)
    selected: list[RagChunk] = []
    tokens = 0
    for result in sorted(results, key=lambda item: (-item.score, item.relative_path, item.start_line)):
        if len(selected) >= limits.max_chunks:
            break
        next_tokens = estimate_tokens(result.text)
        if selected and tokens + next_tokens > limits.max_tokens:
            continue
        selected.append(
            RagChunk(
                id=f"rag_{len(selected) + 1:03d}",
                kind="hybrid_repository_context",
                trust_boundary="untrusted_repository_data",
                title=f"{result.relative_path}:{result.start_line}-{result.end_line}",
                text=result.text,
                file=result.relative_path,
                line=result.start_line,
                end_line=result.end_line,
                symbol=result.symbol_name,
                route=result.metadata.get("route"),
                retrieval_reason=result.retrieval_reason,
                score=result.score,
                metadata={"sources": result.sources, "score_reasons": result.score_reasons, "stage14": True},
            )
        )
        tokens += next_tokens
    return RagContext(chunks=selected, limits=limits, total_candidates=len(results), truncated=len(selected) < len(results), embeddings_used=True)


async def build_repository_index(
    settings: Settings,
    store: Any,
    scan: Scan,
    root: Path,
    owner_user_id: str | None = None,
    cancellation_checker: Callable[[], Awaitable[bool]] | None = None,
) -> IndexResult:
    started = time.perf_counter()
    provider = embedding_provider(settings)
    if settings.embeddings_enabled:
        provider.health(load=True)
    index_id = new_id("ridx")
    store.create_repository_index_job(index_id, scan, owner_user_id, settings, status="running")
    result = IndexResult(
        index_id=index_id,
        scan_id=scan.id,
        project_id=scan.project_id,
        status="running",
        embedding_model=provider.model_name,
        embedding_provider=provider.provider_name,
        embedding_dimension=provider.dimension,
    )
    cancel_event = threading.Event()
    monitor_task: asyncio.Task[None] | None = None

    async def check_cancelled() -> None:
        if cancellation_checker and await cancellation_checker():
            cancel_event.set()
        if cancel_event.is_set():
            raise RepositoryIndexCancelled("Repository intelligence indexing was cancelled.")

    async def monitor_cancelled() -> None:
        while True:
            if cancellation_checker and await cancellation_checker():
                cancel_event.set()
                return
            await asyncio.sleep(0.05)

    if cancellation_checker:
        monitor_task = asyncio.create_task(monitor_cancelled())
    try:
        await check_cancelled()
        chunks, stats = await asyncio.to_thread(make_chunks, root, scan, settings, cancel_event.is_set)
        await check_cancelled()
        result.files_discovered = stats.get("files_discovered", 0)
        result.files_indexed = stats.get("files_indexed", 0)
        result.files_skipped = stats.get("files_skipped", 0)
        result.chunks_generated = len(chunks)
        existing_hashes = store.repository_chunk_hashes(scan.id, owner_user_id)
        changed_chunks = chunks
        result.vectors_reused = 0
        vector_store = VectorStore(settings, provider.dimension)
        vector_health = await vector_store.health()
        if settings.embeddings_enabled and settings.vector_store == "qdrant" and vector_health.get("status") == "ok":
            await vector_store.ensure_collection()
            await check_cancelled()
            if existing_hashes:
                await vector_store.delete_scan(scan.id)
                result.vectors_deleted = len(existing_hashes)
            await check_cancelled()
            for start in range(0, len(changed_chunks), max(1, settings.embedding_batch_size)):
                await check_cancelled()
                batch = changed_chunks[start : start + max(1, settings.embedding_batch_size)]
                vectors = await run_embedding_call(
                    provider.embed_documents,
                    [chunk.text for chunk in batch],
                    timeout_seconds=settings.embedding_timeout_seconds,
                    max_concurrency=settings.embedding_max_concurrency,
                )
                await check_cancelled()
                await vector_store.upsert(batch, vectors)
                result.chunks_embedded += len(batch)
                result.vectors_added += len(batch)
        else:
            result.errors.append(f"Vector store unavailable or embeddings disabled: {vector_health.get('message') or vector_health.get('status')}")
        store.save_repository_index(index_id, scan, owner_user_id, settings, chunks, result)
        result.status = "completed" if not result.errors else "partial"
    except RepositoryIndexCancelled as exc:
        result.status = "cancelled"
        result.errors.append(str(exc))
        store.fail_repository_index_job(index_id, owner_user_id, str(exc), result)
    except Exception as exc:
        result.status = "failed"
        result.errors.append(str(exc))
        store.fail_repository_index_job(index_id, owner_user_id, str(exc), result)
    finally:
        if monitor_task:
            monitor_task.cancel()
            try:
                await monitor_task
            except asyncio.CancelledError:
                pass
    result.duration_ms = int((time.perf_counter() - started) * 1000)
    store.complete_repository_index_job(index_id, owner_user_id, result)
    return result


async def hybrid_search(
    settings: Settings,
    store: Any,
    *,
    scan: Scan,
    query: str,
    owner_user_id: str | None = None,
    findings: list[Finding] | None = None,
    limit: int | None = None,
) -> SearchResponse:
    started = time.perf_counter()
    clean_query = query.strip()[: settings.retrieval_max_query_chars]
    final_limit = max(1, min(limit or settings.retrieval_final_k, settings.retrieval_final_k, 50))
    top_k = max(final_limit, min(settings.retrieval_top_k, 100))
    chunks = store.list_repository_chunks(scan.id, owner_user_id)
    terms = set(re.findall(r"[A-Za-z0-9_.$:/-]{2,}", clean_query.lower()))
    vector_scores: dict[str, float] = {}
    vector_error: str | None = None
    vector_health = {"status": "not_used"}
    if settings.embeddings_enabled and settings.vector_store == "qdrant":
        try:
            provider = embedding_provider(settings)
            provider.health(load=True)
            vector_store = VectorStore(settings, provider.dimension)
            vector_health = await vector_store.health()
            if vector_health.get("status") == "ok":
                query_vector = await run_embedding_call(
                    provider.embed_query,
                    clean_query,
                    timeout_seconds=settings.embedding_timeout_seconds,
                    max_concurrency=settings.embedding_max_concurrency,
                )
                vector_rows = await vector_store.search(query_vector, owner_filter={"scan_id": scan.id, "project_id": scan.project_id}, limit=top_k)
                for row in vector_rows:
                    vector_scores[str(row.get("id"))] = float(row.get("score") or 0.0)
            else:
                vector_error = vector_health.get("message") or "vector store unavailable"
        except Exception as exc:
            vector_health = {"status": "failed", "message": str(exc)}
            vector_error = str(exc)
    results: list[RetrievalResult] = []
    for chunk in chunks:
        scores = {
            "exact": exact_score(clean_query, chunk),
            "keyword": keyword_score(terms, chunk),
            "graph": graph_score(scan, chunk),
            "vector": min(1.0, max(0.0, vector_scores.get(chunk.id, 0.0))),
            "finding": finding_centered_score(findings or [], chunk),
        }
        if max(scores.values()) <= 0:
            continue
        sources = [source for source, score in scores.items() if score > 0]
        results.append(result_from_chunk(chunk, sources, scores))
    results.sort(key=lambda item: (-item.score, item.relative_path, item.start_line))
    return SearchResponse(
        query=clean_query,
        scan_id=scan.id,
        project_id=scan.project_id,
        results=results[:final_limit],
        diagnostics={
            "total_chunks": len(chunks),
            "candidate_results": len(results),
            "vector_health": vector_health,
            "vector_error": vector_error,
            "rag_version": RAG_VERSION,
            "index_schema_version": INDEX_SCHEMA_VERSION,
            "chunker_version": CHUNKER_VERSION,
            "duration_ms": int((time.perf_counter() - started) * 1000),
        },
    )
