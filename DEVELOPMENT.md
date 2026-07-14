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
