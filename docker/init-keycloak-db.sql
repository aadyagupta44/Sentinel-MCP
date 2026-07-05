-- Runs once on first Postgres init (mounted into docker-entrypoint-initdb.d).
-- Keycloak needs its own database alongside the sentinel audit database; both
-- live in the single Postgres instance to keep the demo footprint small.
SELECT 'CREATE DATABASE keycloak'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'keycloak')\gexec
