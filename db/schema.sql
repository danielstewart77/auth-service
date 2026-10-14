-- auth-service: shared login for Daniel's personal sites (backlog, property
-- lens, btc, apps, the hive console, ...). Keyed on username; who may reach
-- which site is a matter of groups and site grants, not of separate accounts.
-- A db created before groups existed is brought up to this shape by
-- registry.Registry._migrate at startup.
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  user_id       TEXT PRIMARY KEY,        -- uuid
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email         TEXT COLLATE NOCASE,     -- where a password-reset link is sent
  password_hash TEXT,                    -- scrypt$n$r$p$salt$digest; NULL = no password sign-in
  created_at    TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0,
  must_change   INTEGER NOT NULL DEFAULT 0  -- set by an admin-issued temp password
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

-- Groups exist for administration. Membership of `admins` is the admin role:
-- an admin passes /verify with no site named and on every site.
CREATE TABLE IF NOT EXISTS groups (
  name       TEXT PRIMARY KEY COLLATE NOCASE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
  group_name TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
  user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  PRIMARY KEY (group_name, user_id)
);

CREATE INDEX IF NOT EXISTS group_members_by_user ON group_members(user_id);

-- Which named sites a non-admin may reach (GET /verify?site=<name>).
CREATE TABLE IF NOT EXISTS site_grants (
  user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  site    TEXT NOT NULL COLLATE NOCASE,
  PRIMARY KEY (user_id, site)
);
