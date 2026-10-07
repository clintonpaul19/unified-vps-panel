# Database migrations

PostgreSQL is the source of truth for the control plane. Production deploys must apply database changes before the application rollout. The application does not run destructive migrations at startup.

platform/db/schema.sql is the bootstrap schema for a new database. Existing databases receive additive migrations through the deployment pipeline.

Current migration set:

- migrations/002_cursor_indexes.sql — adds composite indexes required by cursor-paginated server, command and audit queries.

The migration is idempotent and can safely be applied more than once. The schema is intentionally kept as plain SQL so it can be reviewed, backed up, and applied by standard PostgreSQL tooling.

A future migration runner such as Alembic can adopt the same SQL ordering without changing the API model layer.
