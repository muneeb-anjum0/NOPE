# NOPE

Your app works. That does not mean it is secure.

NOPE is a local-first, evidence-driven application security orchestration platform. Security scanners find evidence, the pipeline organizes it, the code graph connects it, RAG retrieves only what matters, Qwen can reason over focused context, tests verify the result, and rescanning checks the fix.

## Current status

NOPE is a working local MVP, not a finished production platform. The current build includes:

- FastAPI orchestration API.
- Next.js dashboard.
- ZIP repository ingestion with Zip Slip protections.
- Authorized URL scan path with scope checks.
- Stack detection.
- Attack-surface mapping.
- Lightweight code graph.
- NOPE deterministic rule pack.
- Scanner plugin contracts for Semgrep, Gitleaks, OSV-Scanner, Trivy, Checkov, Hadolint, Bandit, and ecosystem audit adapters.
- Finding normalization, deduplication, scoring, verdicts, coverage tracking, and reports.
- Optional Qwen/local-AI configuration with graceful failure.
- Docker Compose stack with web, API, worker, Postgres, Redis, and MinIO.

External scanner CLIs and a local Qwen runtime are intentionally not faked. If they are unavailable, NOPE marks that coverage as failed, skipped, or not tested.

## Pipeline DFD

```mermaid
%%{init: {
  "theme": "base",
  "themeVariables": {
    "background": "#f7f7f4",
    "primaryColor": "#ffffff",
    "primaryTextColor": "#171717",
    "primaryBorderColor": "#d9d8d1",
    "lineColor": "#0f766e",
    "secondaryColor": "#eef6f4",
    "tertiaryColor": "#fff7ed",
    "fontFamily": "Inter, Segoe UI, sans-serif"
  }
}}%%
flowchart LR
  classDef actor fill:#151916,color:#f4f5f1,stroke:#151916,stroke-width:1px
  classDef boundary fill:#fff7ed,color:#171717,stroke:#a16207,stroke-width:1px,stroke-dasharray: 5 4
  classDef process fill:#ffffff,color:#171717,stroke:#0f766e,stroke-width:1.5px
  classDef store fill:#eef6f4,color:#171717,stroke:#1d4ed8,stroke-width:1.2px
  classDef external fill:#fef2f2,color:#171717,stroke:#b42318,stroke-width:1.2px
  classDef partial fill:#f8fafc,color:#475569,stroke:#94a3b8,stroke-width:1px,stroke-dasharray: 3 3

  Dev["Developer / Security Reviewer"]:::actor
  UI["NOPE Web UI<br/>Dashboard, Findings, Coverage, Reports"]:::process
  API["NOPE API<br/>FastAPI orchestration"]:::process
  Auth["Authorization Scope Guard<br/>ownership confirmation, approved hosts, private-IP blocking"]:::process

  subgraph Inputs["Authorized Inputs"]
    Repo["Repository ZIP<br/>or GitHub repository"]:::external
    Url["Authorized URL"]:::external
    Creds["Optional test credentials<br/>and scan policy"]:::external
  end

  subgraph TrustBoundary["Hostile Input Boundary"]
    Ingest["Secure Ingestion<br/>size limits, Zip Slip checks, temp workspace"]:::boundary
    Sandbox["Sandbox Contract<br/>Docker, limits, no host secrets"]:::boundary
  end

  subgraph Pipeline["Evidence Pipeline"]
    Stack["Stack Detection<br/>languages, frameworks, data systems"]:::process
    Surface["Attack Surface Mapping<br/>routes, handlers, auth hints, inputs"]:::process
    Graph["Code Graph<br/>routes -> files -> data/sinks"]:::process
    Orchestrator["Scanner Plugin Orchestrator<br/>health, applicability, failures visible"]:::process
    Rules["NOPE Rules Engine<br/>secrets, authz, CORS, Supabase, AI abuse"]:::process
    URLScan["URL Scanner<br/>headers, cookies, exposed paths, redirects"]:::process
    Normalize["Normalize + Deduplicate<br/>fingerprints, merged evidence"]:::process
    Coverage["Coverage Calculator<br/>Verified, Partial, Failed, Not tested"]:::process
    Score["Score + Verdict<br/>not tested is not secure"]:::process
  end

  subgraph Intelligence["Focused Intelligence Layer"]
    RAG["Focused Retrieval<br/>only relevant evidence snippets"]:::process
    Qwen["Optional Qwen Adapter<br/>local runtime, graceful failure"]:::partial
  end

  subgraph Stores["Local Stores"]
    Memory["Development Store<br/>projects, scans, findings"]:::store
    Postgres["Postgres<br/>planned durable persistence"]:::partial
    MinIO["MinIO<br/>planned artifacts/reports"]:::partial
    Redis["Redis<br/>planned queued jobs"]:::partial
  end

  subgraph Outputs["Outputs"]
    Findings["Normalized Findings<br/>severity, confidence, evidence"]:::store
    AttackMap["Attack Map"]:::store
    Reports["Reports<br/>JSON, Markdown, SARIF-like"]:::store
    PR["GitHub PR / Patch Flow<br/>requires GitHub permissions"]:::partial
  end

  Dev --> UI
  UI --> API
  Repo --> Ingest
  Url --> Auth
  Creds --> Auth
  Auth --> API
  Ingest --> API
  API --> Stack --> Surface --> Graph
  API --> Orchestrator
  Orchestrator --> Rules
  Orchestrator --> URLScan
  Rules --> Normalize
  URLScan --> Normalize
  Graph --> Normalize
  Normalize --> RAG --> Qwen
  Qwen --> Normalize
  Normalize --> Findings --> Coverage --> Score
  Graph --> AttackMap
  Score --> UI
  Findings --> UI
  Coverage --> UI
  AttackMap --> UI
  Findings --> Reports
  Coverage --> Reports
  Reports --> UI
  API --> Memory
  API -.next phase.-> Postgres
  API -.next phase.-> MinIO
  API -.next phase.-> Redis
  Sandbox -.deep scan path.-> Orchestrator
  Reports -.future.-> PR
```

## Local endpoints

- Web UI: `http://localhost:3000`
- API: `http://localhost:8000`
- API docs: `http://localhost:8000/docs`
- MinIO UI: `http://localhost:9001`

## Run

```bash
docker compose up --build -d
```

```bash
docker compose down
```

## Local development

API:

```bash
cd apps/api
python -m pip install -r requirements-dev.txt
python -m pytest
python -m uvicorn nope_api.main:app --reload --port 8000
```

Web:

```bash
pnpm install
pnpm --dir apps/web dev
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web build
```

## Scan modes

URL-only:

- Requires explicit authorization confirmation.
- Blocks private-network and localhost targets by default.
- Checks security headers, cookies, exposed paths, CORS, and redirects.
- Clearly reports that source code was not inspected.

Repository-only:

- Accepts ZIP uploads.
- Extracts into a temporary workspace with size, file-count, symlink, and path traversal protections.
- Runs stack detection, attack-surface mapping, code graph construction, NOPE rules, scanner adapters, deduplication, coverage, and reports.
- Clearly reports when runtime behavior was not verified.

Full scan:

- Combines repository and URL checks.
- Provides the contract for sandbox, dynamic testing, focused retrieval, and optional AI review.
- Deep sandbox execution and ZAP-style crawling are still partial and tracked in `FEATURE_STATUS.md`.

## API highlights

- `GET /health`
- `POST /api/scans/url`
- `POST /api/scans/repository`
- `POST /api/scans/full`
- `GET /api/scans`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/findings`
- `GET /api/scans/{scan_id}/coverage`
- `GET /api/scans/{scan_id}/attack-map`
- `GET /api/scans/{scan_id}/report.json`
- `GET /api/scans/{scan_id}/report.md`
- `GET /api/scans/{scan_id}/report.sarif`
- `GET /api/settings/model`
- `POST /api/settings/model/test`

See `API_REFERENCE.md` for more detail.

## Verification snapshot

Last verified locally:

- `python -m pytest`: passed, 9 tests.
- `python -m compileall nope_api tests`: passed.
- `pnpm --dir apps/web lint`: passed.
- `pnpm --dir apps/web typecheck`: passed.
- `pnpm --dir apps/web build`: passed.
- `docker compose up --build -d`: passed.
- Docker services healthy: `NOPE`, `nope-api`, `nope-postgres`, `nope-redis`, `nope-minio`.
- API health returned `status: ok`.
- Web UI returned HTTP 200.
- MinIO console returned HTTP 200.
- Vulnerable ZIP fixture scan completed and produced real NOPE-rule findings.

Known verification caveats:

- Ruff lint was not completed because the Ruff wheel download stalled locally.
- External scanner CLIs were not installed locally or in the API image.
- Qwen/Ollama/llama.cpp runtime was not present.
- npm reported two moderate frontend dependency advisories during Docker install.

## Important docs

- `ARCHITECTURE.md` - system architecture and data flow.
- `SECURITY_MODEL.md` - scan authorization, upload, sandbox, secret, and failure-safety model.
- `FEATURE_STATUS.md` - continuously updated feature matrix.
- `IMPLEMENTATION_WORKLOG.md` - implementation and verification log.
- `DEVELOPMENT.md` - local development commands.
- `DEPLOYMENT.md` - Docker deployment notes.
- `API_REFERENCE.md` - API endpoint reference.

## README maintenance

Keep this README current whenever one of these changes:

- Run commands.
- Exposed ports or service names.
- Completed features.
- Known limitations.
- Verification results.
- Docker service health behavior.
- Scanner or AI runtime support.

The rule of the house: do not call a feature complete unless it was implemented and verified.
