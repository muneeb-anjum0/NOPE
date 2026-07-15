# NOPE Development

## Prerequisites

- Node.js 22+ or 24+
- pnpm 10+
- Python 3.11+
- Docker and Docker Compose

## Local API

```bash
cd apps/api
python -m venv .venv
.venv/Scripts/activate
pip install -r requirements-dev.txt
uvicorn nope_api.main:app --reload --port 8000
```

## Local Web

```bash
cd apps/web
pnpm install
pnpm dev
```

## Frontend Architecture

- `/` is the public landing page.
- `/app/projects/local/*` contains the local workspace.
- Global design tokens and component styles live in `apps/web/app/globals.css`.
- Shared app components live in `apps/web/components`.
- API fetch helpers and UI data types live in `apps/web/lib`.

## AI Service Development

Use `LOCAL_AI.md` for model path, llama.cpp, CPU/GPU profiles, and troubleshooting. The backend AI adapter lives in `apps/api/nope_api/ai.py`.

## Tests

```bash
cd apps/api
python -m pytest
cd ../web
pnpm lint
pnpm typecheck
pnpm build
```

## Docker

```bash
docker compose up --build
docker compose down
docker compose down -v
```

## Scanner CLIs

NOPE runs scanner plugins when their CLIs exist on PATH. Missing scanner tools are recorded as failed or unavailable coverage rather than producing fake results.
