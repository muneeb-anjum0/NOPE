alter table findings
  add column if not exists status_version integer not null default 1,
  add column if not exists suppressed_until timestamptz,
  add column if not exists suppression_scope text,
  add column if not exists suppression_reason text,
  add column if not exists suppression_actor text;

create table if not exists finding_lifecycle_events (
  id text primary key,
  finding_id text not null,
  scan_id text not null references scans(id) on delete cascade,
  project_id text references projects(id) on delete set null,
  fingerprint text not null,
  previous_status text,
  new_status text not null,
  actor text not null,
  reason text not null,
  scope text not null default 'finding',
  expires_at timestamptz,
  status_version integer not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_findings_project_fingerprint on findings(project_id, fingerprint);
create index if not exists idx_findings_scan_status on findings(scan_id, status);
create index if not exists idx_findings_suppressed_until on findings(suppressed_until) where suppressed_until is not null;
create index if not exists idx_finding_lifecycle_scan_finding on finding_lifecycle_events(scan_id, finding_id, created_at);
create index if not exists idx_finding_lifecycle_fingerprint on finding_lifecycle_events(project_id, fingerprint, created_at);
