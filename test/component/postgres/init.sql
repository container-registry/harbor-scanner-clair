-- Clair's indexer and matcher stores both call uuid_generate_v4(), and the
-- extension is not installed in a stock postgres image.
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- The adapter's scan_job table lives in its own database on the same instance,
-- which is the shape the chart documents. It is owned by the same role the
-- adapter connects as, because the adapter creates the table itself at startup.
-- Postgres has no IF NOT EXISTS for CREATE DATABASE and this file only runs on
-- an empty data directory, so the bare form is correct here.
CREATE DATABASE scanner OWNER clair;
