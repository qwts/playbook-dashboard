-- D1 schema for playbook-dashboard-auth.
--
--   wrangler d1 execute playbook-dashboard-auth --remote --file=schema.sql
--
-- Three tables, three jobs: who has ever signed in, which sessions hold a
-- GitHub actor token, and what privileged actions were attempted. Only the
-- last is load-bearing — a privileged action that cannot be recorded does not
-- happen.

CREATE TABLE IF NOT EXISTS identities (
  provider      TEXT    NOT NULL,
  subject       TEXT    NOT NULL,
  login         TEXT,
  email         TEXT,
  first_seen_at INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL,
  sign_in_count INTEGER NOT NULL DEFAULT 1,
  PRIMARY KEY (provider, subject)
);

-- One row per privileged session. The session id is the key, not the identity:
-- signing out deletes the token, and a second sign-in does not silently extend
-- the life of the first one's credential.
CREATE TABLE IF NOT EXISTS actor_tokens (
  sid                TEXT    PRIMARY KEY,
  provider           TEXT    NOT NULL,
  subject            TEXT    NOT NULL,
  -- AES-GCM ciphertext of the token bundle. D1 is private; this is the second
  -- lock, so a database read is not by itself a live GitHub credential.
  secret             TEXT    NOT NULL,
  access_expires_at  INTEGER,
  refresh_expires_at INTEGER,
  created_at         INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS actor_tokens_identity
  ON actor_tokens (provider, subject);

-- Append-only. `id` is the client's idempotency key, so a replayed submit
-- collides with the row it already wrote instead of acting twice.
CREATE TABLE IF NOT EXISTS audit_log (
  id           TEXT    PRIMARY KEY,
  started_at   INTEGER NOT NULL,
  completed_at INTEGER,
  provider     TEXT    NOT NULL,
  subject      TEXT    NOT NULL,
  login        TEXT,
  action       TEXT    NOT NULL,
  repo         TEXT    NOT NULL,
  target       TEXT    NOT NULL,
  head_sha     TEXT    NOT NULL,
  verb         TEXT    NOT NULL,
  -- 'attempted' until the call returns; then 'succeeded' or 'failed:<code>'.
  -- A row stuck at 'attempted' is the interesting one: the request left here
  -- and nothing came back to say what GitHub did with it.
  outcome      TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_log_actor
  ON audit_log (provider, subject, started_at);
