# NOPE Troubleshooting

## Docker Stack Will Not Start

Check Compose config:

```powershell
docker compose config --quiet
```

Check service state:

```powershell
docker compose ps
docker compose logs --tail 200 nope-api
docker compose logs --tail 200 nope-worker
docker compose logs --tail 200 nope-web
```

If Postgres, Redis, or MinIO volumes are corrupted in a disposable local environment, stop the stack and remove volumes:

```powershell
docker compose down -v
```

This deletes local scan history and artifacts.

## Web UI Cannot Reach API

Verify API health:

```powershell
Invoke-RestMethod http://localhost:8000/health
```

In Docker, `nope-web` uses `API_URL_INTERNAL=http://nope-api:8000` server-side and `NEXT_PUBLIC_API_URL=http://localhost:8000` for browser-facing links. If running the web app outside Docker, set `NEXT_PUBLIC_API_URL=http://localhost:8000`.

## Login Fails

Passwords must be at least eight characters. Repeated failed login attempts are rate-limited for the local account key. Wait for the rate-limit window or use a different local test account.

## Migrations Are Pending

Health output includes migration status:

```powershell
Invoke-RestMethod http://localhost:8000/health | ConvertTo-Json -Depth 6
```

The API applies SQL migrations at startup. To verify explicitly:

```powershell
alembic -c apps/api/alembic.ini upgrade head
alembic -c apps/api/alembic.ini current
```

## Scans Stay Queued

Check queue and worker health with an authenticated token:

```powershell
$login = Invoke-RestMethod http://localhost:8000/api/auth/login -Method Post -ContentType 'application/json' -Body (@{ email='debug@example.com'; password='correct horse battery staple' } | ConvertTo-Json)
$headers = @{ Authorization = "Bearer $($login.token)" }
Invoke-RestMethod http://localhost:8000/api/queue/status -Headers $headers
Invoke-RestMethod http://localhost:8000/api/worker/health -Headers $headers
```

Then inspect worker logs:

```powershell
docker compose logs --tail 200 nope-worker
```

## Scanner Is Missing or Failed

Docker is the verified scanner runtime. Rebuild the API image:

```powershell
docker compose build nope-api nope-worker
docker compose up -d nope-api nope-worker
```

Check scanner capability metadata:

```powershell
Invoke-RestMethod http://localhost:8000/api/scanners/capabilities -Headers $headers
```

Missing or failed scanners are recorded as coverage gaps. NOPE does not fabricate scanner findings.

## Qwen Does Not Load

Verify the model path:

```powershell
Test-Path D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf
```

Start GPU mode:

```powershell
$env:NOPE_MODEL_HOST_DIR='D:/Desktop/Model'
$env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'
$env:NOPE_QWEN_GPU_LAYERS='28'
$env:NOPE_QWEN_GPU_MEMORY_TARGET_MB='5000'
docker compose --profile ai-gpu -f docker-compose.yml -f docker-compose.ai-gpu.yml up -d
```

Check the container:

```powershell
docker compose logs --tail 120 nope-ai
docker exec nope-ai nvidia-smi --query-gpu=name,memory.used,memory.total --format=csv,noheader,nounits
Invoke-RestMethod http://localhost:8081/health
```

If GPU memory is too high or loading fails, reduce `NOPE_QWEN_GPU_LAYERS`. The verified GTX 1060 Max-Q setting is 28 layers under the 5 GB target.

## CPU Fallback

Use CPU profile when NVIDIA support is unavailable:

```powershell
docker compose --profile ai-cpu -f docker-compose.yml -f docker-compose.ai-cpu.yml up -d
```

CPU mode is slower but keeps deterministic scans functional.

## Sandbox Fails

Confirm the runner has Docker access. The worker should remain socketless:

```powershell
docker compose exec -T nope-runner sh -lc "docker version --format '{{.Client.Version}} {{.Server.Version}}'"
docker compose exec -T nope-worker sh -lc "test ! -S /var/run/docker.sock"
```

Confirm sandbox settings:

```powershell
Invoke-RestMethod http://localhost:8000/api/sandbox/health -Headers $headers
```

Repositories without `.nope/sandbox.json` are not applicable for sandbox coverage. A failed sandbox should leave static findings intact and mark dynamic coverage partial or failed.

## PDF Report Missing

Check report status:

```powershell
Invoke-RestMethod http://localhost:8000/api/scans/<scan_id>/reports/pdf/status -Headers $headers
```

Check MinIO and API logs if artifact metadata is missing:

```powershell
docker compose logs --tail 200 nope-minio
docker compose logs --tail 200 nope-api
```

PDF bodies are persisted in Postgres; MinIO stores binary artifacts when reachable.

## GitHub Repositories Are Empty

This is expected without verified GitHub credentials. NOPE stores local GitHub contract settings but does not fake private repository access. Configure and verify real GitHub App/OAuth credentials before expecting repository listings.

## Secret Scan Fails

Run Gitleaks against the changed area:

```powershell
docker compose run --rm --no-deps nope-api gitleaks detect --no-git --redact --source /app/apps/api/nope_api
```

Do not commit `.env`, GGUF models, local artifacts, benchmark outputs, or scanner payloads.
