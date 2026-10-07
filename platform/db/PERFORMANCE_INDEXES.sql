-- Apply once to existing control-plane databases.
create index if not exists idx_servers_org_updated on servers(organization_id, updated_at desc);
create index if not exists idx_servers_org_updated_id on servers(organization_id, updated_at desc, id desc);
create index if not exists idx_commands_server_ready on commands(server_id, status, lease_until, created_at);
create index if not exists idx_commands_server_created on commands(server_id, created_at desc);
create index if not exists idx_commands_server_created_id on commands(server_id, created_at desc, id desc);
create index if not exists idx_audit_org_created on audit_events(organization_id, created_at desc);
create index if not exists idx_audit_org_created_id on audit_events(organization_id, created_at desc, id desc);
