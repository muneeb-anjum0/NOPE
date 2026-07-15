from __future__ import annotations

from hashlib import sha256
from io import BytesIO
import json
from urllib.parse import urlparse

from nope_api.config import Settings
from nope_api.models import new_id


def _endpoint(settings: Settings) -> str:
    parsed = urlparse(settings.minio_endpoint)
    return parsed.netloc or parsed.path


def minio_client(settings: Settings):
    from minio import Minio

    return Minio(
        _endpoint(settings),
        access_key=settings.minio_access_key,
        secret_key=settings.minio_secret_key,
        secure=settings.minio_secure,
    )


def put_json_artifact(
    settings: Settings,
    *,
    scan_id: str,
    artifact_type: str,
    name: str,
    payload: dict,
) -> dict | None:
    body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    if not body.strip():
        return None
    artifact_id = new_id("art")
    object_name = f"scans/{scan_id}/{artifact_id}-{name}.json"
    try:
        client = minio_client(settings)
        if not client.bucket_exists(settings.minio_bucket):
            client.make_bucket(settings.minio_bucket)
        client.put_object(
            settings.minio_bucket,
            object_name,
            BytesIO(body),
            length=len(body),
            content_type="application/json",
        )
    except Exception:
        return None
    return {
        "id": artifact_id,
        "type": artifact_type,
        "filename": f"{name}.json",
        "storage_url": f"minio://{settings.minio_bucket}/{object_name}",
        "size_bytes": len(body),
        "sha256": sha256(body).hexdigest(),
        "object_name": object_name,
    }


def put_binary_artifact(
    settings: Settings,
    *,
    scan_id: str,
    artifact_type: str,
    name: str,
    body: bytes,
    content_type: str,
    extension: str,
) -> dict | None:
    if not body:
        return None
    artifact_id = new_id("art")
    safe_extension = extension.lstrip(".") or "bin"
    object_name = f"scans/{scan_id}/{artifact_id}-{name}.{safe_extension}"
    try:
        client = minio_client(settings)
        if not client.bucket_exists(settings.minio_bucket):
            client.make_bucket(settings.minio_bucket)
        client.put_object(
            settings.minio_bucket,
            object_name,
            BytesIO(body),
            length=len(body),
            content_type=content_type,
        )
    except Exception:
        return None
    return {
        "id": artifact_id,
        "type": artifact_type,
        "filename": f"{name}.{safe_extension}",
        "storage_url": f"minio://{settings.minio_bucket}/{object_name}",
        "size_bytes": len(body),
        "sha256": sha256(body).hexdigest(),
        "object_name": object_name,
        "content_type": content_type,
    }
