# NOPE Deployment

The current deployment target is local Docker Compose.

## Endpoints

- Web UI: `http://localhost:3000`
- API: `http://localhost:8000`
- API Docs: `http://localhost:8000/docs`
- MinIO UI: `http://localhost:9001`

The primary web container is named `NOPE` in Docker Compose.

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
