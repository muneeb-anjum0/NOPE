create table if not exists repository_indexes (
  id text primary key,
  owner_user_id text,
  project_id text references projects(id) on delete cascade,
  scan_id text not null references scans(id) on delete cascade,
  status text not null,
  active boolean not null default false,
  index_schema_version text not null,
  chunker_version text not null,
  embedding_provider text not null,
  embedding_model text not null,
  embedding_dimension integer not null,
  distance_metric text not null default 'Cosine',
  vector_store text not null,
  vector_collection text not null,
  files_discovered integer not null default 0,
  files_indexed integer not null default 0,
  files_skipped integer not null default 0,
  chunks_generated integer not null default 0,
  chunks_embedded integer not null default 0,
  vectors_added integer not null default 0,
  vectors_reused integer not null default 0,
  vectors_deleted integer not null default 0,
  duration_ms integer not null default 0,
  retry_count integer not null default 0,
  cancelled_at timestamptz,
  error_message text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz
);

create unique index if not exists repository_indexes_active_unique
  on repository_indexes(scan_id)
  where active;
create index if not exists repository_indexes_owner_project_idx on repository_indexes(owner_user_id, project_id);
create index if not exists repository_indexes_scan_status_idx on repository_indexes(scan_id, status);

create table if not exists repository_indexed_files (
  id text primary key,
  index_id text not null references repository_indexes(id) on delete cascade,
  owner_user_id text,
  project_id text,
  scan_id text not null,
  relative_path text not null,
  language text not null,
  file_hash text not null,
  byte_size integer not null default 0,
  chunk_count integer not null default 0,
  framework_hints jsonb not null default '[]'::jsonb,
  status text not null default 'indexed',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(index_id, relative_path)
);

create index if not exists repository_indexed_files_scan_path_idx on repository_indexed_files(scan_id, relative_path);

create table if not exists repository_indexed_chunks (
  id text primary key,
  index_id text not null references repository_indexes(id) on delete cascade,
  owner_user_id text,
  project_id text,
  scan_id text not null,
  relative_path text not null,
  language text not null,
  framework_hints jsonb not null default '[]'::jsonb,
  symbol_name text,
  symbol_type text not null,
  start_line integer not null,
  end_line integer not null,
  parent_symbol text,
  imports jsonb not null default '[]'::jsonb,
  exported boolean not null default false,
  route_metadata jsonb not null default '{}'::jsonb,
  auth_relevance boolean not null default false,
  data_access_relevance boolean not null default false,
  storage_relevance boolean not null default false,
  ai_relevance boolean not null default false,
  rule_evidence_refs jsonb not null default '[]'::jsonb,
  content_hash text not null,
  file_hash text not null,
  chunker_version text not null,
  index_schema_version text not null,
  token_estimate integer not null default 1,
  text_preview text not null,
  vector_status text not null default 'pending',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists repository_indexed_chunks_scan_idx on repository_indexed_chunks(scan_id);
create index if not exists repository_indexed_chunks_project_idx on repository_indexed_chunks(owner_user_id, project_id);
create index if not exists repository_indexed_chunks_path_idx on repository_indexed_chunks(scan_id, relative_path);
create index if not exists repository_indexed_chunks_symbol_idx on repository_indexed_chunks(scan_id, symbol_name);
create index if not exists repository_indexed_chunks_hash_idx on repository_indexed_chunks(scan_id, content_hash);

create table if not exists repository_retrieval_sessions (
  id text primary key,
  owner_user_id text,
  project_id text,
  scan_id text not null,
  query text not null,
  query_hash text not null,
  result_count integer not null default 0,
  duration_ms integer not null default 0,
  vector_used boolean not null default false,
  diagnostics jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists repository_retrieval_sessions_scan_idx on repository_retrieval_sessions(scan_id, created_at desc);

create table if not exists repository_retrieval_results (
  id text primary key,
  session_id text not null references repository_retrieval_sessions(id) on delete cascade,
  chunk_id text not null,
  rank integer not null,
  score double precision not null,
  sources jsonb not null default '[]'::jsonb,
  score_reasons jsonb not null default '{}'::jsonb,
  data jsonb not null default '{}'::jsonb
);

create index if not exists repository_retrieval_results_session_rank_idx on repository_retrieval_results(session_id, rank);

create table if not exists repository_index_failures (
  id text primary key,
  owner_user_id text,
  project_id text,
  scan_id text,
  index_id text,
  stage text not null,
  message text not null,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
