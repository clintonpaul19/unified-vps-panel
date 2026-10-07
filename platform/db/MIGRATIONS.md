# Database migrations

PostgreSQL is the source of truth for the control plane. Production deploys must apply database changes before the application rollout. The application does not run destructive migrations at startup.

platform/db/schema.sql is the bootstrap schema for a new database. Existing databases should receive additive SQL migrations through the deployment pipeline (or the team's chosen migration runner) before deploying application code that depends on them.

The schema is intentionally kept as plain SQL so it can be reviewed, backed up, and applied by standard PostgreSQL tooling. The long-term migration seam is compatible with Alembic or another versioned migration runner without changing the application model layer.
