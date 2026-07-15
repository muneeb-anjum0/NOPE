alter table reports
  add column if not exists body text not null default '',
  add column if not exists body_sha256 text,
  add column if not exists byte_size integer not null default 0,
  add column if not exists generated_at timestamptz not null default now();

create index if not exists idx_reports_scan_created on reports(scan_id, created_at desc);
