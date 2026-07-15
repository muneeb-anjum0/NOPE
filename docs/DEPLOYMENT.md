# NOPE Deployment

The current deployment target is local Docker Compose.

## Endpoints

- Web UI: `http://localhost:3000`
- API: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`
- MinIO UI: `http://localhost:9001`
- Qwen debug endpoint: `http://localhost:8081` when an AI profile is enabled

The primary web container is named `NOPE` in Docker Compose.

## AI startup modes

Core mode without AI:

```bash
docker compose up --build -d
```

CPU fallback:

```bash
docker compose -f docker-compose.yml -f docker-compose.ai-cpu.yml --profile ai-cpu up --build -d
```

GPU mode:

```bash
docker compose -f docker-compose.yml -f docker-compose.ai-gpu.yml --profile ai-gpu up --build -d
```

For GPU mode, Docker Desktop/WSL2 must have NVIDIA container support available. The GGUF model directory is mounted read-only from `NOPE_MODEL_HOST_DIR`.

Verified local Qwen settings:

```bash
NOPE_MODEL_HOST_DIR=D:/Desktop/Model
NOPE_MODEL_FILE=Qwen3-8B-Q4_K_M.gguf
NOPE_QWEN_GPU_LAYERS=28
NOPE_QWEN_GPU_MEMORY_TARGET_MB=5000
```

On the local GTX 1060 Max-Q, 28 GPU layers measured 4485 MiB VRAM from inside the CUDA container during Phase 15/16 verification. Earlier Phase 5 samples measured about 4041-4049 MiB. 30 layers failed to fit, so 28 is the highest verified setting under the 5 GB cap.

## Environment

Start from `.env.example`. Production deployments must replace development secrets and configure:

- Persistent PostgreSQL
- Redis
- Object storage
- Session secret
- Encryption key
- GitHub App/OAuth credentials
- AI runtime endpoint if AI analysis is enabled

## Production hardening still required

- Durable database migrations and backups
- External secret manager
- Auth provider and tenant isolation enforcement
- TLS termination
- Centralized logs and metrics
- Container image scanning in CI
- Queue autoscaling and resource quotas
