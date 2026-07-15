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

For GPU mode, Docker Desktop/WSL2 must have NVIDIA container support available. The GGUF model directory is mounted read-only from `NOPE_MODEL_DIR`.

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
