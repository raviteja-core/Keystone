-- +goose Up
-- migrations/authz/0002_authz_tables.sql

CREATE TABLE IF NOT EXISTS authz_tenants (
  tenant_id   text PRIMARY KEY,
  current_rev bigint NOT NULL DEFAULT 0,
  created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS authz_schemas (
  tenant_id   text NOT NULL REFERENCES authz_tenants(tenant_id),
  version     int NOT NULL,
  definition  text NOT NULL,
  parsed      jsonb NOT NULL,
  created_rev bigint NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS authz_tuples (
  tenant_id        text NOT NULL,
  object_type      text NOT NULL,
  object_id        text NOT NULL,
  relation         text NOT NULL,
  subject_type     text NOT NULL,
  subject_id       text NOT NULL,
  subject_relation text NOT NULL DEFAULT '',
  created_rev      bigint NOT NULL,
  deleted_rev      bigint,
  PRIMARY KEY (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation, created_rev)
);

CREATE UNIQUE INDEX IF NOT EXISTS authz_tuples_live_uq ON authz_tuples
  (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation)
  WHERE deleted_rev IS NULL;

CREATE INDEX IF NOT EXISTS authz_tuples_reverse_idx ON authz_tuples
  (tenant_id, subject_type, subject_id, subject_relation, object_type, relation)
  WHERE deleted_rev IS NULL;

CREATE TABLE IF NOT EXISTS authz_changelog (
  tenant_id  text NOT NULL,
  rev        bigint NOT NULL,
  seq        int NOT NULL,
  op         text NOT NULL CHECK (op IN ('touch','create','delete')),
  tuple_text text NOT NULL,
  ts         timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, rev, seq)
);

-- +goose Down
DROP TABLE IF EXISTS authz_changelog;
DROP INDEX IF EXISTS authz_tuples_reverse_idx;
DROP INDEX IF EXISTS authz_tuples_live_uq;
DROP TABLE IF EXISTS authz_tuples;
DROP TABLE IF EXISTS authz_schemas;
DROP TABLE IF EXISTS authz_tenants;
