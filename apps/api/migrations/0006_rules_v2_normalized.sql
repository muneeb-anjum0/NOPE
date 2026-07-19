create table if not exists rules_v2_candidates (
  id text primary key,
  scan_id text not null references scans(id) on delete cascade,
  project_id text references projects(id) on delete set null,
  rule_id text not null,
  rule_version text not null,
  family text not null,
  source_type text not null,
  repository text,
  file text,
  line integer,
  end_line integer,
  symbol text,
  route text,
  preliminary_severity text not null,
  preliminary_confidence text not null,
  framework text,
  affected_resources jsonb not null default '[]'::jsonb,
  missing_evidence jsonb not null default '[]'::jsonb,
  contradictory_evidence jsonb not null default '[]'::jsonb,
  safe_pattern_evidence jsonb not null default '[]'::jsonb,
  scanner_references jsonb not null default '[]'::jsonb,
  related_findings jsonb not null default '[]'::jsonb,
  confidence_factors jsonb not null default '{}'::jsonb,
  data jsonb not null,
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now()
);

create table if not exists rules_v2_candidate_evidence (
  id text primary key,
  candidate_id text not null references rules_v2_candidates(id) on delete cascade,
  scan_id text not null references scans(id) on delete cascade,
  kind text not null,
  source text not null,
  file text,
  line integer,
  end_line integer,
  route text,
  symbol text,
  strength text not null,
  message text not null,
  snippet text,
  metadata jsonb not null default '{}'::jsonb,
  data jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists rules_v2_candidate_correlations (
  id text primary key,
  candidate_id text not null references rules_v2_candidates(id) on delete cascade,
  scan_id text not null references scans(id) on delete cascade,
  correlation_type text not null,
  reference text not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists rules_v2_promotion_history (
  id text primary key,
  candidate_id text not null references rules_v2_candidates(id) on delete cascade,
  scan_id text not null references scans(id) on delete cascade,
  rule_id text not null,
  rule_version text not null,
  result text not null,
  confidence text not null,
  evidence_strength text not null,
  reason text not null,
  machine_reason text,
  missing_evidence jsonb not null default '[]'::jsonb,
  contradictory_evidence jsonb not null default '[]'::jsonb,
  correlation_path jsonb not null default '[]'::jsonb,
  data jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists rules_v2_candidate_suppressions (
  id text primary key,
  candidate_id text not null references rules_v2_candidates(id) on delete cascade,
  scan_id text not null references scans(id) on delete cascade,
  project_id text references projects(id) on delete set null,
  actor text not null,
  reason text not null,
  scope text not null default 'candidate',
  expires_at timestamptz,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_rules_v2_candidates_scan_result on rules_v2_candidates(scan_id, family, rule_id);
create index if not exists idx_rules_v2_candidates_scan_file on rules_v2_candidates(scan_id, file, line);
create index if not exists idx_rules_v2_candidates_project_rule on rules_v2_candidates(project_id, rule_id, last_seen_at);
create index if not exists idx_rules_v2_evidence_candidate on rules_v2_candidate_evidence(candidate_id, strength);
create index if not exists idx_rules_v2_correlations_candidate on rules_v2_candidate_correlations(candidate_id, correlation_type);
create index if not exists idx_rules_v2_history_scan_result on rules_v2_promotion_history(scan_id, result, created_at);
create index if not exists idx_rules_v2_suppressions_active on rules_v2_candidate_suppressions(project_id, candidate_id, expires_at);
