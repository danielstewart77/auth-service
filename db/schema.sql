-- auth-service: shared login for Daniel's personal sites (backlog, property
-- lens, btc, apps, ...). Single service, single account today, but keyed on
-- username so a second account is a row, not a redesign.
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  user_id       TEXT PRIMARY KEY,        -- uuid
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email         TEXT,                    -- where a password-reset link is sent
  password_hash TEXT NOT NULL,           -- scrypt$n$r$p$salt$digest
  created_at    TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0
);

-- Live logins. The column holds sha256(token), never the token, so a
-- readable database is not a set of working sessions. Verified by every
-- personal site via GET /verify — no shared signing secret to distribute.
CREATE TABLE IF NOT EXISTS auth_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_tokens_by_user ON auth_tokens(user_id);

-- Short-lived, single-use tokens for the forgot-password flow. Separate from
-- auth_tokens so a leaked reset token can't be replayed as a session and a
-- reset request never has to touch a live login.
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_by_user ON password_reset_tokens(user_id);
