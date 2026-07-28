from __future__ import annotations

import asyncio
import sys
import time
import types
from pathlib import Path
from typing import Any

import pytest

from nope_api.config import Settings
from nope_api.embeddings import (
    EmbeddingCompatibilityError,
    EmbeddingError,
    HashingEmbeddingProvider,
    SentenceTransformersEmbeddingProvider,
    embedding_provider,
    run_embedding_call,
)
from nope_api.repository_intelligence import QDRANT_COLLECTION, VectorStore


class DummySentenceTransformer:
    calls: list[dict[str, Any]] = []

    def __init__(self, model: str, **kwargs: Any) -> None:
        self.model = model
        self.kwargs = kwargs
        DummySentenceTransformer.calls.append({"model": model, **kwargs})

    def get_sentence_embedding_dimension(self) -> int:
        return 384

    def encode(self, texts, **kwargs):
        rows = []
        for text in texts:
            seed = len(str(text))
            rows.append([float((seed + idx) % 7) / 10.0 for idx in range(384)])
        return rows


def install_dummy_sentence_transformer(monkeypatch: pytest.MonkeyPatch) -> None:
    module = types.ModuleType("sentence_transformers")
    module.SentenceTransformer = DummySentenceTransformer
    monkeypatch.setitem(sys.modules, "sentence_transformers", module)
    DummySentenceTransformer.calls.clear()


def settings(tmp_path: Path, **overrides: Any) -> Settings:
    values = {
        "embedding_provider": "sentence_transformers",
        "embedding_model": "BAAI/bge-small-en-v1.5",
        "embedding_device": "cpu",
        "embedding_cache_dir": tmp_path / "models",
        "embedding_allow_model_download": False,
        "embedding_batch_size": 2,
        "embedding_timeout_seconds": 1,
    }
    values.update(overrides)
    return Settings(**values)


def test_stage14_sentence_transformers_provider_uses_cpu_cache_and_local_files(monkeypatch, tmp_path):
    install_dummy_sentence_transformer(monkeypatch)

    provider = SentenceTransformersEmbeddingProvider(settings(tmp_path))
    vectors = provider.embed_documents(["owner scoped route", "public bucket"])

    assert len(vectors) == 2
    assert len(vectors[0]) == 384
    assert DummySentenceTransformer.calls[0]["model"] == "BAAI/bge-small-en-v1.5"
    assert DummySentenceTransformer.calls[0]["device"] == "cpu"
    assert DummySentenceTransformer.calls[0]["cache_folder"] == str(tmp_path / "models")
    assert DummySentenceTransformer.calls[0]["local_files_only"] is True
    assert provider.health()["metrics"]["documents"] == 2


def test_stage14_embedding_download_is_explicit(monkeypatch, tmp_path):
    install_dummy_sentence_transformer(monkeypatch)

    provider = embedding_provider(settings(tmp_path, embedding_allow_model_download=True))
    provider.health(load=True)

    assert DummySentenceTransformer.calls[0]["local_files_only"] is False


def test_stage14_hashing_provider_is_explicit_test_mode(tmp_path):
    provider = embedding_provider(settings(tmp_path, embedding_provider="local_hashing"))
    assert isinstance(provider, HashingEmbeddingProvider)
    assert provider.provider_name == "local_hashing"
    assert round(sum(value * value for value in provider.embed_query("same text")), 6) == 1.0


def test_stage14_embedding_timeout_is_reported_cleanly():
    def slow_embed(texts):
        time.sleep(0.2)
        return [[0.0] * 384 for _ in texts]

    with pytest.raises(EmbeddingError, match="timed out"):
        asyncio.run(run_embedding_call(slow_embed, ["x"], timeout_seconds=0))


def test_stage14_embedding_concurrency_limit_is_enforced():
    active = 0
    max_active = 0

    def slow_embed(texts):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        time.sleep(0.05)
        active -= 1
        return [[0.0] * 384 for _ in texts]

    async def run_many():
        await asyncio.gather(
            *[
                run_embedding_call(slow_embed, [str(index)], timeout_seconds=1, max_concurrency=1)
                for index in range(6)
            ]
        )

    asyncio.run(run_many())

    assert max_active == 1


class FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RuntimeError(f"status {self.status_code}")


class FakeAsyncClient:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args: Any) -> None:
        return None

    async def get(self, url: str):
        assert url.endswith(f"/collections/{QDRANT_COLLECTION}")
        return FakeResponse(200, {"result": {"config": {"params": {"vectors": {"size": 128, "distance": "Cosine"}}}}})


def test_stage14_qdrant_dimension_mismatch_requires_reindex(monkeypatch, tmp_path):
    monkeypatch.setattr("nope_api.repository_intelligence.httpx.AsyncClient", FakeAsyncClient)
    vector_store = VectorStore(settings(tmp_path, qdrant_url="http://qdrant.local"), dimension=384)

    with pytest.raises(EmbeddingCompatibilityError, match="dimension 128"):
        asyncio.run(vector_store.ensure_collection())
