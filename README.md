# NOPE<span style="color:#f02a56">.</span>

![Local first](https://img.shields.io/badge/local--first-yes-f02a56?style=for-the-badge&labelColor=101211)
![Rules first](https://img.shields.io/badge/rules--first-evidence-f02a56?style=for-the-badge&labelColor=101211)
![AI optional](https://img.shields.io/badge/Qwen-optional-f02a56?style=for-the-badge&labelColor=101211)
![Docker](https://img.shields.io/badge/runtime-Docker-f02a56?style=for-the-badge&labelColor=101211)

**NOPE is a local-first application security scanning dashboard for evidence-driven reviews.**

It accepts authorized repository ZIPs and URLs, runs deterministic scanner evidence first, tracks what was and was not tested, produces reports, and can optionally ask local Qwen through llama.cpp to reason over focused evidence.

NOPE does **not** claim an app is fully secure, compliant, or safe to ship. It shows findings, evidence, coverage gaps, scanner failures, and untested areas.

---

## Quick Q/A

### What does the pipeline do?

The pipeline is the main scan engine.

It:

- validates ZIPs, URLs, project folders, and authorization scope
- extracts repository ZIPs safely
- queues work in Redis
- runs the worker pipeline
- detects stack/frameworks
- builds attack surface and code graph evidence
- runs NOPE rules and bundled scanners
- optionally runs sandbox workflows
- normalizes and deduplicates findings
- calculates coverage, score, and verdict
- persists scans, findings, stages, scanner runs, reports, baselines, and drift data

In short: **the pipeline does the security scanning work.**

### What does RAG do?

RAG does **not** scan the app by itself.

RAG retrieves focused context for Qwen after the pipeline has findings and evidence. It gathers:

- the selected finding
- scanner evidence
- source snippets near affected files
- route and attack-surface context
- code graph edges
- stack evidence
- scanner run metadata
- category-specific security guidance

RAG redacts secrets, marks repository text as untrusted data, removes duplicate chunks, and enforces file/chunk/token limits. It does not currently use embeddings or vector search; it uses deterministic metadata, keyword, route, file, import, and graph scoring.

In short: **RAG prepares focused evidence for AI.**

### What does the AI do?

AI is optional. When enabled, local Qwen runs through the `nope-ai` llama.cpp container.

Qwen can:

- explain a finding
- challenge whether a finding is well-supported
- suggest a fix direction
- suggest regression/security tests
- add an AI review message after a scan

Qwen cannot:

- replace deterministic scanners
- silently downgrade findings
- prove the app is secure
- run the scan by itself
- receive the whole repository as raw context

If Qwen fails, deterministic scan results are preserved.

In short: **AI is the reviewer/explainer layer, not the scanner engine.**

### How do folders work?

Folders are project workspaces. Each folder owns its own ZIP uploads, scan history, findings, reports, baselines, and drift comparisons.

When you switch the active folder in the sidebar, dashboard pages use that folder by default:

- Overview
- Findings
- Attack Map
- Coverage
- Assets
- Reports
- Scans

Different folders do not mix findings or scan history.

### How does drift work?

Drift compares scans inside the same folder/project. It can compare:

- latest scan vs previous matching scan
- scan vs baseline
- explicit scan vs scan

Different project folders are not compared. ZIP scaffold similarity is checked before accepting a new upload into an existing folder; low-similarity ZIPs require an explicit override.

### What does NOPE check?

NOPE combines custom rules, local Semgrep rules, external scanner adapters, URL checks, and optional sandbox checks.

Custom NOPE rules currently check for:

- hardcoded credentials and private keys
- database lookups by ID that may lack owner/tenant scope
- client-provided role, owner, tenant, or admin fields being trusted
- wildcard CORS configuration
- exposed Supabase service-role or server-only keys
- AI calls without nearby rate, token, timeout, or budget controls

Local Semgrep rules currently check for:

- hardcoded secret-like assignments
- wildcard CORS header patterns

Bundled scanner adapters:

| Scanner | Main coverage |
| --- | --- |
| Semgrep | Injection, authorization, authentication, secrets |
| Gitleaks | Secrets |
| OSV-Scanner | Vulnerable dependencies |
| Trivy | Dependencies, containers, CI/CD, secrets, misconfigurations |
| Checkov | Infrastructure, CI/CD, containers |
| Hadolint | Dockerfile/container hygiene |
| Bandit | Python injection and secret patterns |
| NOPE URL scanner | Security headers, staging exposure, URL scope, privacy hints |
| NOPE sandbox / ZAP | Optional dynamic testing when `.nope/sandbox.json` declares safe workflows |

Scanner failures are not hidden. They are recorded as failed or not-applicable coverage.

---

## Data Flow Diagram

```mermaid
%%{init: {
  "flowchart": { "curve": "basis", "htmlLabels": true },
  "theme": "base",
  "themeVariables": {
    "background": "#08090a",
    "primaryColor": "#101211",
    "primaryTextColor": "#f5f7f5",
    "primaryBorderColor": "#f02a56",
    "lineColor": "#f02a56",
    "secondaryColor": "#141716",
    "tertiaryColor": "#191c1b",
    "clusterBkg": "#101211",
    "clusterBorder": "#f02a56",
    "fontFamily": "Inter, Segoe UI, sans-serif"
  }
}}%%
flowchart LR
  subgraph input["Input and UI"]
    direction TB
    user["Operator<br/>authorized user"]
    web["NOPE Web<br/>Next.js dashboard"]
  end

  subgraph control["Control Plane"]
    direction TB
    api["NOPE API<br/>FastAPI orchestration"]
    queue[("Redis<br/>scan queue")]
    db[("Postgres<br/>users, sessions,<br/>scans, findings")]
  end

  subgraph execution["Execution Plane"]
    direction TB
    worker["NOPE Worker<br/>pipeline runner"]
    scanners["Deterministic scanners<br/>Semgrep, Gitleaks, OSV,<br/>Trivy, Checkov, Hadolint, Bandit"]
    sandbox["Optional sandbox<br/>declared workflows and ZAP"]
  end

  subgraph intelligence["Reasoning and Storage"]
    direction TB
    ai["Local Qwen<br/>llama.cpp GGUF runtime"]
    minio[("MinIO<br/>raw artifacts<br/>and report blobs")]
    reports["Reports<br/>JSON, MD, SARIF, PDF"]
  end

  user -->|"login, upload ZIP, set target"| web
  web -->|"server-side requests"| api
  api -->|"session and scan state"| db
  api -->|"enqueue scan job"| queue
  queue -->|"job payload"| worker
  worker -->|"repository and URL evidence"| scanners
  worker -->|"opt-in dynamic checks"| sandbox
  scanners -->|"normalized findings"| worker
  sandbox -->|"bounded runtime evidence"| worker
  worker -->|"findings, coverage, drift"| db
  worker -->|"raw output and generated files"| minio
  worker -->|"focused evidence only"| ai
  ai -->|"review suggestions"| worker
  db -->|"dashboard data"| api
  minio -->|"artifact links"| api
  api -->|"export requests"| reports
  reports -->|"download links"| web
  api -->|"scan state and findings"| web

  classDef lane fill:#0d0f0e,stroke:#f02a56,stroke-width:1.5px,color:#f5f7f5;
  classDef service fill:#101211,stroke:#f02a56,stroke-width:2px,color:#f5f7f5;
  classDef store fill:#141716,stroke:#f02a56,stroke-width:1.5px,color:#f5f7f5;
  class input,control,execution,intelligence lane;
  class user,web,api,worker,scanners,sandbox,ai,reports service;
  class db,queue,minio store;
```

---

## Services

| Service | Container | Purpose |
| --- | --- | --- |
| Web | `NOPE` / `nope-web` | Landing page, login, dashboard |
| API | `nope-api` | Auth, orchestration, settings, reports, scan APIs |
| Worker | `nope-worker` | Redis consumer and scanner execution pipeline |
| Database | `nope-postgres` | Users, sessions, scans, findings, reports, settings |
| Queue | `nope-redis` | Scan queue, cancellation flags, worker heartbeat |
| Object storage | `nope-minio` | Raw scanner artifacts and binary report artifacts |
| AI runtime | `nope-ai` | Optional llama.cpp server for local Qwen |

---

## Local URLs

| Surface | URL |
| --- | --- |
| Web UI | `http://localhost:3000` |
| Login | `http://localhost:3000/login` |
| Dashboard | `http://localhost:3000/app/projects/local` |
| API | `http://localhost:8000` |
| API docs | `http://localhost:8000/docs` |
| MinIO console | `http://localhost:9001` |
| llama.cpp health/debug | `http://localhost:8081` |

Default MinIO development credentials:

```text
username: nope
password: nope-development-password
```

---

## Run Locally

### Core stack, no AI

```powershell
docker compose up --build -d
```

### Full GPU stack with local Qwen

```powershell
$env:NOPE_MODEL_HOST_DIR='D:\Desktop\Model'
$env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'
$env:NOPE_QWEN_GPU_LAYERS='28'
$env:NOPE_QWEN_GPU_MEMORY_TARGET_MB='5000'

docker compose -f docker-compose.yml -f docker-compose.ai-gpu.yml --profile ai-gpu up --build -d
```

### CPU fallback

```powershell
$env:NOPE_MODEL_HOST_DIR='D:\Desktop\Model'
$env:NOPE_MODEL_FILE='Qwen3-8B-Q4_K_M.gguf'

docker compose -f docker-compose.yml -f docker-compose.ai-cpu.yml --profile ai-cpu up --build -d
```

### Shutdown

```powershell
docker compose down
```

Use `docker compose down -v` only when you intentionally want to remove local Postgres, Redis, MinIO, and workspace volumes.

---

## Verified Local AI Settings

| Setting | Value |
| --- | --- |
| Runtime | llama.cpp |
| Host model path | `D:\Desktop\Model\Qwen3-8B-Q4_K_M.gguf` |
| Container model path | `/models/Qwen3-8B-Q4_K_M.gguf` |
| GPU layers | `28` |
| GPU memory target | `5000 MB` |

The verified local GPU setting is 28 layers under the 5 GB VRAM target. Thirty layers previously failed to fit on the development machine.

---

## Development Checks

Backend:

```powershell
$env:PYTHONPATH='apps/api'
python -m pytest apps/api/tests -q
python -m compileall apps/api/nope_api apps/api/tests apps/worker
```

Frontend:

```powershell
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web build
```

Docker:

```powershell
docker compose config --quiet
docker compose build nope-api nope-worker nope-web
```

---

## Security Notes

- Scan only repositories and URLs you own or are explicitly authorized to test.
- ZIP uploads pass archive safety checks before extraction.
- Private-network URL targets are blocked by default.
- Qwen receives focused evidence only, not whole repositories.
- Repository text is treated as untrusted data in RAG prompts.
- Sandbox workflows are opt-in through `.nope/sandbox.json`.
- Sandbox containers do not receive NOPE service secrets, host home directories, or the Docker socket.
- GitHub private access remains blocked until real credentials are supplied and verified.

---

## Docs

| Document | Purpose |
| --- | --- |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | System structure and service boundaries |
| [`docs/PIPELINE.md`](docs/PIPELINE.md) | Scan lifecycle from input to reports |
| [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) | Threat model and local safety boundaries |
| [`docs/API_REFERENCE.md`](docs/API_REFERENCE.md) | API routes and contracts |
| [`docs/LOCAL_AI.md`](docs/LOCAL_AI.md) | Qwen and llama.cpp setup |
| [`docs/SCANNERS.md`](docs/SCANNERS.md) | Scanner behavior and evidence handling |
| [`docs/SANDBOX.md`](docs/SANDBOX.md) | Opt-in dynamic workflow execution |
| [`docs/TROUBLESHOOTING.md`](docs/TROUBLESHOOTING.md) | Common local Docker and runtime issues |
