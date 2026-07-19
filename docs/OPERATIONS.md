# NOPE Operations

NOPE is operated locally through Docker Compose.

## Start

```powershell
$env:NOPE_MODEL_HOST_DIR='D:\Desktop\Model'
$env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'
$env:NOPE_QWEN_GPU_LAYERS='28'
$env:NOPE_QWEN_GPU_MEMORY_TARGET_MB='5000'
docker compose up --build -d
```

The base Compose file starts the local Qwen service when the documented model mount exists.

## Health

```powershell
docker compose ps
Invoke-RestMethod http://localhost:8000/health
Invoke-WebRequest http://localhost:3000/login -UseBasicParsing
```

Public `/health` is intentionally sanitized. Authenticated `/api/health/details` exposes database, scanner, sandbox, and AI detail for local operators.

## Stop

```powershell
docker compose down
```

Use `docker compose down -v` only for clean-room verification or intentional local data reset.

## Migrations

The API applies known SQL migrations on startup. Manual verification:

```powershell
$env:PYTHONPATH='apps/api'
python -m alembic -c apps/api/alembic.ini upgrade head
python -m alembic -c apps/api/alembic.ini current
```

## Backups

Local backups are operator responsibility. Back up Postgres and MinIO volumes before destructive verification.

## Logs

```powershell
docker compose logs --tail=200 nope-api
docker compose logs --tail=200 nope-worker
docker compose logs --tail=200 nope-runner
docker compose logs --tail=200 nope-ai
```

Logs are redacted, but operators should still treat scanner output as sensitive.

## Clean-Room Verification Warning

The final clean-room procedure may remove local Compose volumes. That resets local users, scans, findings, reports, MinIO artifacts, and Redis state.
