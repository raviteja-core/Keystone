-- +goose Up
-- migrations/authz/0001_init.sql

CREATE TABLE IF NOT EXISTS schemas (
  tenant_id   text NOT NULL,
  version     int NOT NULL,
  schema_text text NOT NULL,
  compiled    jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, version)
);

CREATE TABLE IF NOT EXISTS revisions (
  tenant_id        text PRIMARY KEY,
  current_revision bigint NOT NULL DEFAULT 0,
  updated_at       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tuples (
  id               bigserial PRIMARY KEY,
  tenant_id        text NOT NULL,
  object_type      text NOT NULL,
  object_id        text NOT NULL,
  relation         text NOT NULL,
  subject_type     text NOT NULL,
  subject_id       text NOT NULL,
  subject_relation text NOT NULL DEFAULT '',
  created_revision bigint NOT NULL,
  deleted_revision bigint,
  created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS tuples_unique_active ON tuples (tenant_id, object_type, object_id, relation, subject_type, subject_id, subject_relation) WHERE deleted_revision IS NULL;
CREATE INDEX IF NOT EXISTS tuples_lookup_idx ON tuples (tenant_id, object_type, object_id, relation) WHERE deleted_revision IS NULL;
CREATE INDEX IF NOT EXISTS tuples_subject_idx ON tuples (tenant_id, subject_type, subject_id) WHERE deleted_revision IS NULL;

-- +goose Down
DROP TABLE IF EXISTS tuples;
DROP TABLE IF EXISTS revisions;
DROP TABLE IF EXISTS schemas;
