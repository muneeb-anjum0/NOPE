create table if not exists local_users (
  id text primary key,
  email text unique not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists local_sessions (
  token text primary key,
  user_id text not null references local_users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);

create table if not exists projects (
  id text primary key,
  owner_user_id text references local_users(id) on delete set null,
  name text not null,
  repository text,
  target_url text,
  created_at timestamptz not null default now()
);

create table if not exists project_targets (
  id text primary key,
  project_id text not null references projects(id) on delete cascade,
  target_url text not null,
  approved_hosts jsonb not null default '[]'::jsonb,
  excluded_paths jsonb not null default '[]'::jsonb,
  authorization_confirmed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists repository_sources (
  id text primary key,
  project_id text references projects(id) on delete cascade,
  source_type text not null,
  repository_name text,
  url text,
  created_at timestamptz not null default now()
);

create table if not exists repository_snapshots (
  id text primary key,
  project_id text references projects(id) on delete cascade,
  repository_source_id text references repository_sources(id) on delete set null,
  branch text,
  commit_sha text,
  upload_name text,
  uploaded_artifact_id text,
  created_at timestamptz not null default now()
);

create table if not exists scans (
  id text primary key,
  owner_user_id text references local_users(id) on delete set null,
  project_id text references projects(id) on delete set null,
  mode text not null,
  status text not null,
  verdict text not null,
  score integer not null default 0,
  coverage_percent integer not null default 0,
  target_url text,
  repository_name text,
  branch text,
  commit_sha text,
  started_at timestamptz not null,
  completed_at timestamptz,
  data jsonb not null
);

create table if not exists scan_stages (
  id bigserial primary key,
  scan_id text not null references scans(id) on delete cascade,
  position integer not null,
  name text not null,
  status text not null,
  message text,
  started_at timestamptz,
  completed_at timestamptz,
  data jsonb not null default '{}'::jsonb
);

create table if not exists scanner_runs (
  id bigserial primary key,
  scan_id text not null references scans(id) on delete cascade,
  scanner text not null,
  version text not null default 'unknown',
  status text not null,
  coverage_categories jsonb not null default '[]'::jsonb,
  started_at timestamptz,
  completed_at timestamptz,
  message text not null default '',
  findings_count integer not null default 0,
  raw_artifact_id text,
  data jsonb not null default '{}'::jsonb
);

create table if not exists findings (
  id text primary key,
  scan_id text not null references scans(id) on delete cascade,
  project_id text references projects(id) on delete set null,
  fingerprint text not null,
  title text not null,
  description text not null,
  severity text not null,
  confidence text not null,
  category text not null,
  cwe text,
  owasp text,
  affected_file text,
  affected_route text,
  remediation text not null,
  status text not null,
  first_seen timestamptz,
  last_seen timestamptz,
  fix_available boolean not null default false,
  verified boolean not null default false,
  data jsonb not null
);

create table if not exists finding_evidence (
  id bigserial primary key,
  finding_id text not null references findings(id) on delete cascade,
  source text not null,
  file text,
  line integer,
  route text,
  snippet text,
  message text not null,
  data jsonb not null default '{}'::jsonb
);

create table if not exists finding_sources (
  id bigserial primary key,
  finding_id text not null references findings(id) on delete cascade,
  scanner_source text not null,
  unique (finding_id, scanner_source)
);

create table if not exists finding_history (
  id bigserial primary key,
  finding_id text references findings(id) on delete cascade,
  fingerprint text not null,
  scan_id text references scans(id) on delete cascade,
  event text not null,
  event_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create table if not exists scan_coverage (
  id bigserial primary key,
  scan_id text not null references scans(id) on delete cascade,
  domain text not null,
  status text not null,
  scanners jsonb not null default '[]'::jsonb,
  notes text not null default '',
  unique (scan_id, domain)
);

create table if not exists reports (
  id text primary key,
  scan_id text not null references scans(id) on delete cascade,
  format text not null,
  media_type text not null,
  storage_url text,
  status text not null default 'generated',
  created_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb,
  unique (scan_id, format)
);

create table if not exists model_configurations (
  id text primary key,
  owner_user_id text references local_users(id) on delete set null,
  provider text not null,
  model_name text not null,
  runtime_endpoint text not null,
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists scanner_configurations (
  id text primary key,
  owner_user_id text references local_users(id) on delete set null,
  scanner text not null,
  enabled boolean not null default true,
  timeout_seconds integer,
  settings jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists application_settings (
  id text primary key,
  owner_user_id text references local_users(id) on delete set null,
  key text not null,
  value jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (owner_user_id, key)
);

create table if not exists security_baselines (
  id text primary key,
  project_id text references projects(id) on delete cascade,
  scan_id text references scans(id) on delete set null,
  name text not null,
  created_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create table if not exists drift_events (
  id text primary key,
  baseline_id text references security_baselines(id) on delete cascade,
  scan_id text references scans(id) on delete cascade,
  event_type text not null,
  severity text,
  message text not null,
  created_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create table if not exists uploaded_artifacts (
  id text primary key,
  owner_user_id text references local_users(id) on delete set null,
  project_id text references projects(id) on delete set null,
  scan_id text references scans(id) on delete set null,
  artifact_type text not null,
  filename text,
  storage_url text,
  size_bytes bigint,
  sha256 text,
  created_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create table if not exists job_artifacts (
  id text primary key,
  scan_id text references scans(id) on delete cascade,
  job_id text,
  artifact_type text not null,
  storage_url text,
  created_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create table if not exists audit_logs (
  id bigserial primary key,
  owner_user_id text references local_users(id) on delete set null,
  project_id text references projects(id) on delete set null,
  scan_id text references scans(id) on delete set null,
  action text not null,
  actor text,
  created_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create table if not exists github_connections (
  id text primary key,
  owner_user_id text references local_users(id) on delete cascade,
  provider text not null default 'github',
  status text not null default 'blocked_missing_credentials',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create table if not exists github_installations (
  id text primary key,
  connection_id text references github_connections(id) on delete cascade,
  installation_id text,
  account_login text,
  permissions jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create table if not exists github_repository_references (
  id text primary key,
  installation_id text references github_installations(id) on delete cascade,
  full_name text not null,
  default_branch text,
  private boolean,
  created_at timestamptz not null default now(),
  data jsonb not null default '{}'::jsonb
);

create index if not exists idx_projects_owner_created on projects(owner_user_id, created_at desc);
create index if not exists idx_scans_owner_started on scans(owner_user_id, started_at desc);
create index if not exists idx_scans_project_started on scans(project_id, started_at desc);
create index if not exists idx_scans_status on scans(status);
create index if not exists idx_findings_scan_severity on findings(scan_id, severity);
create index if not exists idx_findings_fingerprint on findings(fingerprint);
create index if not exists idx_scanner_runs_scan on scanner_runs(scan_id);
create index if not exists idx_scan_coverage_scan on scan_coverage(scan_id);
create index if not exists idx_reports_scan_format on reports(scan_id, format);
