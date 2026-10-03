-- +goose Up
-- migrations/auth/0001_init.sql

CREATE TABLE IF NOT EXISTS users (
  id                 uuid PRIMARY KEY,
  email              text NOT NULL,
  email_verified     boolean NOT NULL DEFAULT false,
  username           text,
  display_name       text,
  password_hash      text NOT NULL,
  status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
  external_id        text,
  mfa_enabled        boolean NOT NULL DEFAULT false,
  failed_login_count int NOT NULL DEFAULT 0,
  locked_until       timestamptz,
  version            int NOT NULL DEFAULT 1,
  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_uq    ON users (lower(email));
CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uq ON users (lower(username)) WHERE username IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_external_id_uq    ON users (external_id)     WHERE external_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS clients (
  id                          uuid PRIMARY KEY,
  client_id                   text NOT NULL UNIQUE,
  client_secret_hash          bytea,
  name                        text NOT NULL,
  client_type                 text NOT NULL CHECK (client_type IN ('public','confidential')),
  token_endpoint_auth_method  text NOT NULL CHECK (token_endpoint_auth_method IN ('none','client_secret_basic','client_secret_post')),
  redirect_uris               text[] NOT NULL DEFAULT '{}',
  post_logout_redirect_uris   text[] NOT NULL DEFAULT '{}',
  allowed_grant_types         text[] NOT NULL,
  allowed_scopes              text[] NOT NULL,
  allowed_audiences           text[] NOT NULL DEFAULT '{}',
  default_audience            text,
  require_consent             boolean NOT NULL DEFAULT true,
  access_token_ttl_seconds    int,
  created_at                  timestamptz NOT NULL DEFAULT now(),
  disabled_at                 timestamptz,
  CHECK ( (client_type = 'public') = (client_secret_hash IS NULL) )
);

CREATE TABLE IF NOT EXISTS sessions (
  id_hash       bytea PRIMARY KEY,
  user_id       uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  auth_time     timestamptz NOT NULL,
  amr           text[] NOT NULL,
  ip            inet,
  user_agent    text,
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,
  revoked_at    timestamptz
);

CREATE TABLE IF NOT EXISTS authorization_codes (
  code_hash      bytea PRIMARY KEY,
  client_id      text NOT NULL REFERENCES clients(client_id),
  user_id        uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  redirect_uri   text NOT NULL,
  scope          text NOT NULL,
  nonce          text,
  code_challenge text NOT NULL,
  auth_time      timestamptz NOT NULL,
  amr            text[] NOT NULL,
  session_hash   bytea,
  expires_at     timestamptz NOT NULL,
  used_at        timestamptz,
  created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id                   uuid PRIMARY KEY,
  token_hash           bytea NOT NULL UNIQUE,
  family_id            uuid NOT NULL,
  parent_id            uuid REFERENCES refresh_tokens(id),
  client_id            text NOT NULL REFERENCES clients(client_id),
  user_id              uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  scope                text NOT NULL,
  session_hash         bytea,
  issued_at            timestamptz NOT NULL DEFAULT now(),
  expires_at           timestamptz NOT NULL,
  absolute_expires_at  timestamptz NOT NULL,
  rotated_at           timestamptz,
  revoked_at           timestamptz,
  revoked_reason       text
);
CREATE INDEX IF NOT EXISTS refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX IF NOT EXISTS refresh_tokens_user_idx   ON refresh_tokens (user_id);

CREATE TABLE IF NOT EXISTS consents (
  user_id    uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  client_id  text NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
  scope      text NOT NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (user_id, client_id)
);

CREATE TABLE IF NOT EXISTS signing_keys (
  kid          text PRIMARY KEY,
  alg          text NOT NULL DEFAULT 'RS256',
  public_jwk   jsonb NOT NULL,
  private_enc  bytea NOT NULL,
  status       text NOT NULL CHECK (status IN ('pending','active','retired','revoked')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  activate_at  timestamptz,
  retire_at    timestamptz
);
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_active ON signing_keys ((true)) WHERE status = 'active';

-- +goose Down
DROP TABLE IF EXISTS signing_keys;
DROP TABLE IF EXISTS consents;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS authorization_codes;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS clients;
DROP TABLE IF EXISTS users;
