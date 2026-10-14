"""The schema migration that runs at startup against a pre-multi-user db."""

import sqlite3

import pytest

import auth
import seed as seed_mod
from config import Settings
from registry import Registry

# The schema every live db was created with before groups existed.
LEGACY_SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE users (
  user_id       TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email         TEXT,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL,
  disabled      INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE auth_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
CREATE INDEX auth_tokens_by_user ON auth_tokens(user_id);
CREATE TABLE password_reset_tokens (
  token_hash TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used       INTEGER NOT NULL DEFAULT 0
);
"""

FAR_FUTURE = "2999-01-01T00:00:00+00:00"


@pytest.fixture()
def legacy_db(tmp_path):
    path = tmp_path / "auth.db"
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_SCHEMA)
    conn.execute(
        "INSERT INTO users VALUES ('u-daniel', 'daniel', 'd@example.com', ?, "
        "'2026-07-24T00:00:00+00:00', 0)",
        (auth.hash_password("daniels-pw"),),
    )
    conn.execute(
        "INSERT INTO users VALUES ('u-svc', 'skippy-service', '', ?, "
        "'2026-07-25T00:00:00+00:00', 0)",
        (auth.hash_password("svc-pw"),),
    )
    conn.execute(
        "INSERT INTO auth_tokens VALUES (?, 'u-daniel', '2026-07-24T00:00:00+00:00', ?)",
        (auth.token_digest("daniels-live-token"), FAR_FUTURE),
    )
    conn.commit()
    conn.close()
    return path


def _settings(seed_username="daniel"):
    return Settings(seed_username=seed_username, seed_password="")


def _boot(path, seed_username="daniel"):
    """What server.py does at import: open the registry, then seed."""
    reg = Registry(path)
    seed_mod.seed(reg, _settings(seed_username))
    return reg


def test_existing_users_passwords_and_sessions_survive(legacy_db):
    reg = _boot(legacy_db)
    try:
        daniel = reg.user_by_username("daniel")
        assert daniel["user_id"] == "u-daniel"
        assert daniel["email"] == "d@example.com"
        assert auth.verify_password("daniels-pw", daniel["password_hash"])
        assert not daniel["must_change"]
        assert reg.user_by_username("skippy-service")["user_id"] == "u-svc"
        assert reg.user_for_token(auth.token_digest("daniels-live-token"))["user_id"] == "u-daniel"
    finally:
        reg.close()


def test_only_the_seeded_account_joins_admins(legacy_db):
    reg = _boot(legacy_db)
    try:
        assert reg.groups_for("u-daniel") == ["admins"]
        assert reg.groups_for("u-svc") == []
    finally:
        reg.close()


def test_migrated_db_accepts_an_account_with_no_password(legacy_db):
    reg = _boot(legacy_db)
    try:
        user = reg.create_user("aiden", None, email="aiden@example.com")
        assert reg.get_user(user["user_id"])["password_hash"] is None
    finally:
        reg.close()


def test_migration_is_idempotent_and_never_readds_a_removed_admin(legacy_db):
    reg = _boot(legacy_db)
    reg.add_member("admins", "u-svc")
    reg.remove_member("admins", "u-daniel")
    reg.close()

    reg = _boot(legacy_db)
    try:
        assert reg.groups_for("u-daniel") == []
        assert reg.groups_for("u-svc") == ["admins"]
        assert reg.count_users() == 2
        assert reg.user_for_token(auth.token_digest("daniels-live-token"))["user_id"] == "u-daniel"
    finally:
        reg.close()


def test_without_a_matching_seed_name_the_first_account_becomes_admin(legacy_db):
    reg = _boot(legacy_db, seed_username="")
    try:
        assert reg.groups_for("u-daniel") == ["admins"]
        assert reg.groups_for("u-svc") == []
    finally:
        reg.close()


def test_fresh_db_seed_creates_admins_with_the_seeded_user(tmp_path):
    reg = Registry(tmp_path / "auth.db")
    try:
        seed_mod.seed(reg, Settings(seed_username="daniel", seed_password="pw-123"))
        daniel = reg.user_by_username("daniel")
        assert reg.groups_for(daniel["user_id"]) == ["admins"]
    finally:
        reg.close()
