create table if not exists recon_runs (
  id bigserial primary key,
  created_at timestamptz not null default now(),
  tool text not null,
  target text not null,
  attack_tactic text not null,
  attack_technique text not null,
  stdout text,
  network jsonb not null
);

create table if not exists findings (
  id text primary key,
  recon_run_id bigint references recon_runs(id) on delete set null,
  host text,
  severity text,
  title text not null,
  status text not null,
  technique text not null,
  evidence jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now()
);

create index if not exists idx_recon_runs_created_at on recon_runs (created_at desc);
create index if not exists idx_recon_runs_tool on recon_runs (tool);
create index if not exists idx_findings_severity on findings (severity);
create index if not exists idx_findings_status on findings (status);
create index if not exists idx_findings_technique on findings (technique);
