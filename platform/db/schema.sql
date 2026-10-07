create extension if not exists pgcrypto;

create table if not exists organizations (id uuid primary key default gen_random_uuid(), name text not null, slug text not null unique, created_at timestamptz not null default now());

create table if not exists users (id uuid primary key default gen_random_uuid(), email text not null unique, password_hash text not null, is_active boolean not null default true, created_at timestamptz not null default now(), last_login_at timestamptz);

create table if not exists memberships (organization_id uuid not null references organizations(id) on delete cascade, user_id uuid not null references users(id) on delete cascade, role text not null check (role in ('owner','admin','operator','viewer')), created_at timestamptz not null default now(), primary key (organization_id, user_id));
create index if not exists idx_memberships_user on memberships(user_id);

create table if not exists servers (id uuid primary key default gen_random_uuid(), organization_id uuid not null references organizations(id) on delete cascade, name text not null, hostname text, public_ipv4 inet, public_ipv6 inet, agent_version text, status text not null default 'offline' check (status in ('online','offline','degraded','provisioning')), metrics jsonb not null default '{}'::jsonb, last_seen_at timestamptz, created_at timestamptz not null default now(), updated_at timestamptz not null default now(), unique (organization_id, name));
create index if not exists idx_servers_org_status on servers(organization_id, status);
create index if not exists idx_servers_org_updated on servers(organization_id, updated_at desc);
create index if not exists idx_servers_last_seen on servers(last_seen_at desc);

create table if not exists server_tokens (id uuid primary key default gen_random_uuid(), server_id uuid not null references servers(id) on delete cascade, token_hash bytea not null unique, created_at timestamptz not null default now(), revoked_at timestamptz);
create index if not exists idx_server_tokens_server_active on server_tokens(server_id, revoked_at);

create table if not exists commands (id uuid primary key default gen_random_uuid(), organization_id uuid not null references organizations(id) on delete cascade, server_id uuid not null references servers(id) on delete cascade, command_type text not null, payload jsonb not null default '{}'::jsonb, status text not null default 'queued' check (status in ('queued','sent','running','succeeded','failed','expired','cancelled')), idempotency_key text, requested_by uuid references users(id) on delete set null, created_at timestamptz not null default now(), started_at timestamptz, finished_at timestamptz, lease_until timestamptz, attempt_count integer not null default 0, error text, result jsonb);
create unique index if not exists uq_commands_org_idempotency on commands(organization_id, idempotency_key) where idempotency_key is not null;
create index if not exists idx_commands_server_status_created on commands(server_id, status, created_at desc);
create index if not exists idx_commands_server_ready on commands(server_id, status, lease_until, created_at);
create index if not exists idx_commands_server_created on commands(server_id, created_at desc);
create index if not exists idx_commands_lease on commands(status, lease_until);

create table if not exists audit_events (id bigserial primary key, organization_id uuid not null references organizations(id) on delete cascade, actor_user_id uuid references users(id) on delete set null, server_id uuid references servers(id) on delete set null, event_type text not null, metadata jsonb not null default '{}'::jsonb, created_at timestamptz not null default now());
create index if not exists idx_audit_org_created on audit_events(organization_id, created_at desc);