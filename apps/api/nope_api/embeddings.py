from __future__ import annotations

import asyncio
import hashlib
import math
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from nope_api.config import Settings


class EmbeddingError(RuntimeError):
    """Base error for local embedding failures."""


class EmbeddingModelUnavailable(EmbeddingError):
    """Raised when the configured local model or dependency is missing."""


class EmbeddingCompatibilityError(EmbeddingError):
    """Raised when persisted vectors are incompatible with current settings."""


_EMBEDDING_SEMAPHORES: dict[int, asyncio.Semaphore] = {}


def _embedding_semaphore(max_concurrency: int) -> asyncio.Semaphore:
    bounded = max(1, int(max_concurrency or 1))
    semaphore = _EMBEDDING_SEMAPHORES.get(bounded)
    if semaphore is None:
        semaphore = asyncio.Semaphore(bounded)
        _EMBEDDING_SEMAPHORES[bounded] = semaphore
    return semaphore


@dataclass
class EmbeddingMetrics:
    provider: str
    model: str
    device: str
    dimension: int
    batches: int = 0
    documents: int = 0
    queries: int = 0
    total_latency_ms: int = 0
    last_latency_ms: int = 0
    last_error: str | None = None

    def record(self, *, documents: int, latency_ms: int, query: bool = False) -> None:
        self.batches += 1
        self.documents += documents
        self.queries += 1 if query else 0
        self.last_latency_ms = latency_ms
        self.total_latency_ms += latency_ms
        self.last_error = None

    def fail(self, exc: Exception) -> None:
        self.last_error = str(exc)

    def as_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "device": self.device,
            "dimension": self.dimension,
            "batches": self.batches,
            "documents": self.documents,
            "queries": self.queries,
            "total_latency_ms": self.total_latency_ms,
            "last_latency_ms": self.last_latency_ms,
            "last_error": self.last_error,
        }


@dataclass
class BaseEmbeddingProvider:
    settings: Settings
    dimension: int = 384
    model_revision: str = "unknown"
    _metrics: EmbeddingMetrics = field(init=False)

    def __post_init__(self) -> None:
        self._metrics = EmbeddingMetrics(
            provider=self.provider_name,
            model=self.model_name,
            device=self.settings.embedding_device,
            dimension=self.dimension,
        )

    @property
    def provider_name(self) -> str:
        return self.settings.embedding_provider

    @property
    def model_name(self) -> str:
        return self.settings.embedding_model

    def health(self, *, load: bool = False) -> dict[str, Any]:
        return {
            "status": "ok",
            "provider": self.provider_name,
            "model": self.model_name,
            "revision": self.model_revision,
            "device": self.settings.embedding_device,
            "dimension": self.dimension,
            "cache_dir": str(self.settings.embedding_cache_dir),
            "metrics": self._metrics.as_dict(),
        }

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        raise NotImplementedError

    def embed_query(self, text: str) -> list[float]:
        return self.embed_documents([text])[0]


class HashingEmbeddingProvider(BaseEmbeddingProvider):
    """Explicit deterministic provider for tests and offline troubleshooting."""

    def __post_init__(self) -> None:
        self.dimension = 384
        self.model_revision = "deterministic-test-provider"
        super().__post_init__()

    @property
    def provider_name(self) -> str:
        return "local_hashing"

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        started = time.perf_counter()
        try:
            vectors = [self._hash_embedding(f"{self.settings.embedding_document_prefix}{text}") for text in texts]
            self._metrics.record(documents=len(texts), latency_ms=int((time.perf_counter() - started) * 1000))
            return vectors
        except Exception as exc:
            self._metrics.fail(exc)
            raise

    def embed_query(self, text: str) -> list[float]:
        started = time.perf_counter()
        try:
            vector = self._hash_embedding(f"{self.settings.embedding_query_prefix}{text}")
            self._metrics.record(documents=1, latency_ms=int((time.perf_counter() - started) * 1000), query=True)
            return vector
        except Exception as exc:
            self._metrics.fail(exc)
            raise

    def _hash_embedding(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        tokens = re.findall(r"[A-Za-z0-9_.$:/-]{2,}", text.lower())
        if not tokens:
            return vector
        for token in tokens:
            digest = hashlib.blake2b(token.encode("utf-8", errors="ignore"), digest_size=8).digest()
            index = int.from_bytes(digest[:4], "big") % self.dimension
            sign = 1.0 if digest[4] & 1 else -1.0
            vector[index] += sign * (1.0 + min(len(token), 24) / 24.0)
        norm = math.sqrt(sum(item * item for item in vector)) or 1.0
        return [item / norm for item in vector]


class SentenceTransformersEmbeddingProvider(BaseEmbeddingProvider):
    _model: Any = None
    _load_error: str | None = None

    @property
    def provider_name(self) -> str:
        return "sentence_transformers"

    def _load(self) -> Any:
        if self._model is not None:
            return self._model
        try:
            from sentence_transformers import SentenceTransformer  # type: ignore
        except Exception as exc:
            self._load_error = str(exc)
            raise EmbeddingModelUnavailable(
                "sentence-transformers is not installed. Install the pinned API requirements and rebuild the API/worker image."
            ) from exc

        cache_dir = Path(self.settings.embedding_cache_dir)
        cache_dir.mkdir(parents=True, exist_ok=True)
        try:
            self._model = SentenceTransformer(
                self.settings.embedding_model,
                device=self.settings.embedding_device,
                cache_folder=str(cache_dir),
                revision=self.settings.embedding_model_revision or None,
                local_files_only=not self.settings.embedding_allow_model_download,
                trust_remote_code=False,
            )
        except TypeError:
            self._model = SentenceTransformer(
                self.settings.embedding_model,
                device=self.settings.embedding_device,
                cache_folder=str(cache_dir),
                revision=self.settings.embedding_model_revision or None,
                local_files_only=not self.settings.embedding_allow_model_download,
            )
        except Exception as exc:
            self._load_error = str(exc)
            raise EmbeddingModelUnavailable(
                "Local embedding model is unavailable. Run the explicit model download command or set "
                "NOPE_EMBEDDING_ALLOW_MODEL_DOWNLOAD=true for a one-time controlled download."
            ) from exc
        dimension_getter = getattr(self._model, "get_embedding_dimension", None)
        if dimension_getter is None:
            dimension_getter = self._model.get_sentence_embedding_dimension
        self.dimension = int(dimension_getter())
        if self.dimension <= 0:
            raise EmbeddingCompatibilityError(f"Embedding model reported invalid dimension: {self.dimension}")
        self.model_revision = self.settings.embedding_model_revision or getattr(self._model, "_model_card_vars", {}).get("model_name", "local")
        self._metrics.dimension = self.dimension
        return self._model

    def health(self, *, load: bool = False) -> dict[str, Any]:
        status = "ok"
        message = None
        if load:
            try:
                self._load()
            except Exception as exc:
                status = "failed"
                message = str(exc)
        payload = super().health(load=load)
        payload.update(
            {
                "status": status,
                "message": message,
                "download_allowed": self.settings.embedding_allow_model_download,
                "loaded": self._model is not None,
                "load_error": self._load_error,
            }
        )
        return payload

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        started = time.perf_counter()
        try:
            model = self._load()
            prefixed = [f"{self.settings.embedding_document_prefix}{text}" for text in texts]
            vectors = model.encode(
                prefixed,
                batch_size=max(1, self.settings.embedding_batch_size),
                normalize_embeddings=self.settings.embedding_normalize,
                show_progress_bar=False,
            )
            rows = [list(map(float, vector)) for vector in vectors]
            for vector in rows:
                if len(vector) != self.dimension:
                    raise EmbeddingCompatibilityError(
                        f"Embedding dimension mismatch: expected {self.dimension}, got {len(vector)}"
                    )
            self._metrics.record(documents=len(texts), latency_ms=int((time.perf_counter() - started) * 1000))
            return rows
        except Exception as exc:
            self._metrics.fail(exc)
            raise

    def embed_query(self, text: str) -> list[float]:
        started = time.perf_counter()
        try:
            model = self._load()
            vectors = model.encode(
                [f"{self.settings.embedding_query_prefix}{text}"],
                batch_size=1,
                normalize_embeddings=self.settings.embedding_normalize,
                show_progress_bar=False,
            )
            vector = list(map(float, vectors[0]))
            if len(vector) != self.dimension:
                raise EmbeddingCompatibilityError(f"Embedding dimension mismatch: expected {self.dimension}, got {len(vector)}")
            self._metrics.record(documents=1, latency_ms=int((time.perf_counter() - started) * 1000), query=True)
            return vector
        except Exception as exc:
            self._metrics.fail(exc)
            raise


def embedding_provider(settings: Settings) -> BaseEmbeddingProvider:
    provider = settings.embedding_provider.lower().strip()
    if provider == "sentence_transformers":
        return SentenceTransformersEmbeddingProvider(settings)
    if provider in {"local_hashing", "fake", "test"}:
        return HashingEmbeddingProvider(settings)
    raise EmbeddingModelUnavailable(f"Unsupported embedding provider: {settings.embedding_provider}")


async def run_embedding_call(
    func: Callable[..., list[list[float]] | list[float]],
    *args: Any,
    timeout_seconds: float,
    max_concurrency: int = 1,
) -> list[list[float]] | list[float]:
    try:
        bounded_timeout = max(0.001, float(timeout_seconds))
        async with _embedding_semaphore(max_concurrency):
            return await asyncio.wait_for(asyncio.to_thread(func, *args), timeout=bounded_timeout)
    except asyncio.TimeoutError as exc:
        raise EmbeddingError(f"Embedding call timed out after {timeout_seconds}s") from exc
