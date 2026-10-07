-- Additive migration for existing control-plane databases.
-- Safe to run more than once.
alter table commands
  add column if not exists lease_token text;
