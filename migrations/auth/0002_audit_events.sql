-- +goose Up
-- migrations/auth/0002_audit_events.sql

CREATE TABLE IF NOT EXISTS audit_events (
  id          bigserial PRIMARY KEY,
  ts          timestamptz NOT NULL DEFAULT now(),
  actor_type  text NOT NULL,
  actor_id    text,
  action      text NOT NULL,
  target_type text,
  target_id   text,
  outcome     text NOT NULL CHECK (outcome IN ('success','failure')),
  ip          inet,
  user_agent  text,
  request_id  text,
  metadata    jsonb NOT NULL DEFAULT '{}',
  prev_hash   bytea NOT NULL,
  hash        bytea NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_events_ts_idx ON audit_events (ts);
CREATE INDEX IF NOT EXISTS audit_events_action_idx ON audit_events (action);
CREATE INDEX IF NOT EXISTS audit_events_actor_idx ON audit_events (actor_id);

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION audit_events_immutable() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'audit_events is append-only';
END;
$$ LANGUAGE plpgsql;
-- +goose StatementEnd

DROP TRIGGER IF EXISTS audit_no_update ON audit_events;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION audit_events_immutable();

DROP TRIGGER IF EXISTS audit_no_truncate ON audit_events;
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION audit_events_immutable();

-- +goose StatementBegin
DO $$
BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'keystone_auth_app') THEN
    GRANT SELECT, INSERT ON audit_events TO keystone_auth_app;
    GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO keystone_auth_app;
  END IF;
END;
$$;
-- +goose StatementEnd

-- +goose Down
DROP TRIGGER IF EXISTS audit_no_truncate ON audit_events;
DROP TRIGGER IF EXISTS audit_no_update ON audit_events;
-- +goose StatementBegin
DROP FUNCTION IF EXISTS audit_events_immutable();
-- +goose StatementEnd
DROP TABLE IF EXISTS audit_events;
