-- Enable UUID generation (choose ONE depending on your environment)
create extension if not exists "pgcrypto";

-- =========================
-- 1) Principals (Upstream identity)
-- =========================
create table if not exists principals (
  -- You can either:
  -- (1) store a UUID you generate, OR
  -- (2) store a deterministic hash of "iss|sub" as text.
  --
  -- Recommended: UUID primary key + unique(iss, sub)
  id uuid primary key default gen_random_uuid(),

  iss text not null,
  sub text not null,

  created_at timestamptz not null default now(),

  -- Each user identity should be unique per issuer
  constraint principals_iss_sub_unique unique (iss, sub)
);

create index if not exists idx_principals_iss on principals (iss);
create index if not exists idx_principals_sub on principals (sub);

-- =========================
-- 2) Notion Connections (Downstream OAuth tokens)
-- =========================
create table if not exists notion_connections (
  id uuid primary key default gen_random_uuid(),

  principal_id uuid not null references principals(id) on delete cascade,

  -- Notion workspace identifier (store as text to avoid assumptions)
  workspace_id text not null,

  -- Store encrypted tokens (application-level encryption recommended)
  access_token_enc text not null,
  refresh_token_enc text null,

  -- If you track expiration; nullable because some providers don't provide it
  expires_at timestamptz null,

  -- Soft revoke
  revoked_at timestamptz null,

  -- Extra fields returned by Notion OAuth / future extensions
  meta jsonb not null default '{}'::jsonb,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  -- You typically want one connection per user per workspace
  constraint notion_connections_principal_workspace_unique unique (principal_id, workspace_id)
);

create index if not exists idx_notion_connections_principal_id
  on notion_connections (principal_id);

create index if not exists idx_notion_connections_workspace_id
  on notion_connections (workspace_id);

create index if not exists idx_notion_connections_revoked_at
  on notion_connections (revoked_at);

-- Optional: query JSONB metadata efficiently later
create index if not exists idx_notion_connections_meta_gin
  on notion_connections using gin (meta);

-- =========================
-- 3) OAuth state storage (Phase 1) 
-- =========================
create table if not exists oauth_states (
  -- Store the raw state string (random, high entropy)
  state text primary key,

  created_at timestamptz not null default now(),
  expires_at timestamptz not null,

  -- One-time use marker
  consumed_at timestamptz null,

  -- In later phases you can bind state -> principal
  principal_id uuid null references principals(id) on delete set null
);

create index if not exists idx_oauth_states_expires_at
  on oauth_states (expires_at);

create index if not exists idx_oauth_states_consumed_at
  on oauth_states (consumed_at);

-- =========================
-- 4) updated_at auto-update trigger (optional)
-- =========================
create or replace function set_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

drop trigger if exists trg_notion_connections_updated_at on notion_connections;
create trigger trg_notion_connections_updated_at
before update on notion_connections
for each row execute function set_updated_at();
