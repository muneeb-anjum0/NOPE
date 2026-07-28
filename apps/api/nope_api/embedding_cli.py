from __future__ import annotations

import argparse
import json
from pathlib import Path

from nope_api.config import Settings
from nope_api.embeddings import embedding_provider


def _settings(args: argparse.Namespace) -> Settings:
    return Settings(
        embedding_provider="sentence_transformers",
        embedding_model=args.model,
        embedding_model_revision=args.revision or "",
        embedding_cache_dir=Path(args.cache_dir),
        embedding_device=args.device,
        embedding_allow_model_download=args.download,
        embedding_batch_size=args.batch_size,
    )


def cmd_download(args: argparse.Namespace) -> int:
    settings = _settings(args).model_copy(update={"embedding_allow_model_download": True})
    provider = embedding_provider(settings)
    health = provider.health(load=True)
    sample = provider.embed_query("NOPE local CPU embedding smoke test")
    print(
        json.dumps(
            {
                "status": health["status"],
                "provider": provider.provider_name,
                "model": provider.model_name,
                "revision": provider.model_revision,
                "device": settings.embedding_device,
                "dimension": provider.dimension,
                "cache_dir": str(settings.embedding_cache_dir),
                "sample_norm": round(sum(value * value for value in sample), 6),
            },
            indent=2,
        )
    )
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    settings = _settings(args)
    provider = embedding_provider(settings)
    docs = provider.embed_documents(["server-side owner check", "public bucket exposure"])
    query = provider.embed_query("owner authorization route")
    print(
        json.dumps(
            {
                "status": "ok",
                "provider": provider.provider_name,
                "model": provider.model_name,
                "revision": provider.model_revision,
                "device": settings.embedding_device,
                "dimension": provider.dimension,
                "documents": len(docs),
                "query_dimension": len(query),
                "metrics": provider.health()["metrics"],
            },
            indent=2,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage NOPE local embedding models.")
    parser.add_argument("command", choices=["download", "smoke"])
    parser.add_argument("--model", default="BAAI/bge-small-en-v1.5")
    parser.add_argument("--revision", default="")
    parser.add_argument("--cache-dir", default="/app/.nope-model-cache")
    parser.add_argument("--device", default="cpu")
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--download", action="store_true", help="Allow a controlled model download for this run.")
    args = parser.parse_args()
    if args.command == "download":
        return cmd_download(args)
    return cmd_smoke(args)


if __name__ == "__main__":
    raise SystemExit(main())

