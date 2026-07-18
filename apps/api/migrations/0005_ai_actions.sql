create table if not exists ai_action_cache (
  cache_key text primary key,
  owner_user_id text references local_users(id) on delete set null,
  finding_fingerprint text not null,
  action text not null,
  provider text not null,
  model text not null,
  quantization text,
  prompt_version text not null,
  rag_version text not null,
  evidence_hash text not null,
  settings_hash text not null,
  result jsonb not null,
  context_metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  last_used_at timestamptz not null default now()
);

create table if not exists ai_action_jobs (
  id text primary key,
  owner_user_id text references local_users(id) on delete set null,
  scan_id text references scans(id) on delete cascade,
  finding_id text not null,
  finding_fingerprint text not null,
  action text not null,
  status text not null,
  provider text not null,
  model text not null,
  quantization text,
  prompt_version text not null,
  rag_version text not null,
  evidence_hash text not null,
  settings_hash text not null,
  cache_key text not null,
  queued_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  cancelled_at timestamptz,
  latency_ms integer,
  cached boolean not null default false,
  message text not null default '',
  context_chunks integer not null default 0,
  result jsonb,
  error_code text,
  error_message text,
  metadata jsonb not null default '{}'::jsonb
);

create index if not exists idx_ai_action_cache_owner_expiry on ai_action_cache(owner_user_id, expires_at);
create index if not exists idx_ai_action_cache_fingerprint_action on ai_action_cache(owner_user_id, finding_fingerprint, action);
create index if not exists idx_ai_action_jobs_owner_status on ai_action_jobs(owner_user_id, status, queued_at);
create index if not exists idx_ai_action_jobs_scan_finding on ai_action_jobs(scan_id, finding_id, queued_at);
