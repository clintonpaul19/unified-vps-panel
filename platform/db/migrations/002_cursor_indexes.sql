-- Additive migration for existing control-plane databases.
-- Safe to run more than once.
create index if not exists idx_servers_org_updated_id
  on servers(organization_id, updated_at desc, id desc);

create index if not exists idx_commands_server_created_id
  on commands(server_id, created_at desc, id desc);

create index if not exists idx_audit_org_created_id
  on audit_events(organization_id, created_at desc, id desc);
