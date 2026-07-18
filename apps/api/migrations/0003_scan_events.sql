create table if not exists scan_events (
  id text primary key,
  scan_id text not null references scans(id) on delete cascade,
  stage_id text,
  scanner_run_id text,
  event_type text not null,
  previous_state text,
  new_state text,
  progress integer,
  message text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  error_code text,
  error_details text,
  attempt integer not null default 1,
  worker_identity text,
  created_at timestamptz not null default now(),
  sequence integer not null,
  idempotency_key text not null,
  unique (scan_id, sequence),
  unique (scan_id, idempotency_key)
);

create index if not exists idx_scan_events_scan_sequence on scan_events(scan_id, sequence);
create index if not exists idx_scan_events_scan_created on scan_events(scan_id, created_at);
create index if not exists idx_scan_events_type on scan_events(event_type);
