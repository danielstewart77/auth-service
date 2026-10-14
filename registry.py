"""SQLite persistence: users, groups, site grants, live sessions, reset tokens."""

from __future__ import annotations

import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

_SCHEMA_PATH = Path(__file__).resolve().parent / "db" / "schema.sql"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


ADMINS = "admins"


class Conflict(Exception):
    """A write refused because of what is already stored (HTTP 409)."""


class LastAdmin(Conflict):
    """The write would leave the hive with no enabled admin."""


class Registry:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        # One connection is shared by every request thread, so a transaction
        # opened by one must not be committed halfway by another.
        self._lock = threading.RLock()
        self._conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
        self._conn.commit()
        self._migrate()

    def close(self) -> None:
        self._conn.close()

    @contextmanager
    def _tx(self):
        """One write transaction, taken with the db's write lock up front."""
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.rollback()
                raise
            self._conn.commit()

    # -- migration -----------------------------------------------------

    def _migrate(self) -> None:
        """Bring a db created before groups existed up to schema.sql's shape.

        Idempotent: every step tests the db for what it would do first. The
        users table is rebuilt (sqlite cannot drop NOT NULL in place) with
        foreign keys off, so dropping the old table cascades into nothing —
        every live session and reset token keeps its user_id.
        """
        columns = {
            r["name"] for r in self._conn.execute("PRAGMA table_info(users)")
        }
        if "must_change" not in columns:
            self._conn.execute("PRAGMA foreign_keys = OFF")
            try:
                with self._tx() as c:
                    c.execute(
                        "CREATE TABLE users_new ("
                        " user_id TEXT PRIMARY KEY,"
                        " username TEXT NOT NULL UNIQUE COLLATE NOCASE,"
                        " email TEXT COLLATE NOCASE,"
                        " password_hash TEXT,"
                        " created_at TEXT NOT NULL,"
                        " disabled INTEGER NOT NULL DEFAULT 0,"
                        " must_change INTEGER NOT NULL DEFAULT 0)"
                    )
                    c.execute(
                        "INSERT INTO users_new (user_id, username, email, password_hash,"
                        " created_at, disabled, must_change) "
                        "SELECT user_id, username, email, password_hash, created_at,"
                        " disabled, 0 FROM users"
                    )
                    c.execute("DROP TABLE users")
                    c.execute("ALTER TABLE users_new RENAME TO users")
                    broken = c.execute("PRAGMA foreign_key_check").fetchall()
                    if broken:
                        raise RuntimeError(f"users rebuild broke foreign keys: {broken}")
            finally:
                self._conn.execute("PRAGMA foreign_keys = ON")
        with self._lock:
            self._conn.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique "
                "ON users(email COLLATE NOCASE) WHERE email IS NOT NULL AND email != ''"
            )
            self._conn.commit()

    def ensure_admins_group(self, seed_username: str) -> bool:
        """Create the `admins` group if missing; True when it was created now.

        At creation the seeded account joins it — or, if no account has that
        name, the earliest one (the seed always creates the first account).
        Only at creation: after that membership is the admins' own business,
        and a restart must never put back an admin someone took out.
        """
        with self._tx() as c:
            created = c.execute(
                "INSERT OR IGNORE INTO groups (name, created_at) VALUES (?, ?)",
                (ADMINS, _now()),
            ).rowcount
            if not created:
                return False
            row = c.execute(
                "SELECT user_id FROM users WHERE username = ? COLLATE NOCASE",
                (seed_username,),
            ).fetchone() if seed_username else None
            if row is None:
                row = c.execute(
                    "SELECT user_id FROM users ORDER BY created_at, rowid LIMIT 1"
                ).fetchone()
            if row is not None:
                c.execute(
                    "INSERT INTO group_members (group_name, user_id) VALUES (?, ?)",
                    (ADMINS, row["user_id"]),
                )
            return True

    # -- users ---------------------------------------------------------

    def count_users(self) -> int:
        with self._lock:
            return self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(
        self,
        username: str,
        password_hash: str | None,
        email: str = "",
        must_change: bool = False,
        sites: Iterable[str] = (),
    ) -> dict[str, Any]:
        """Insert a user and its site grants in one transaction.

        Raises Conflict on a taken username or email, and then nothing —
        neither the user nor any grant — is written.
        """
        user_id = str(uuid.uuid4())
        try:
            with self._tx() as c:
                c.execute(
                    "INSERT INTO users (user_id, username, email, password_hash,"
                    " created_at, must_change) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, username, email or "", password_hash, _now(), int(must_change)),
                )
                c.executemany(
                    "INSERT OR IGNORE INTO site_grants (user_id, site) VALUES (?, ?)",
                    [(user_id, site) for site in sites],
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("username or email already in use") from exc
        return self.get_user(user_id)

    def list_users(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM users ORDER BY username"
            ).fetchall()
        return [dict(r) for r in rows]

    def set_email(self, user_id: str, email: str) -> None:
        try:
            with self._tx() as c:
                c.execute(
                    "UPDATE users SET email = ? WHERE user_id = ?", (email or "", user_id)
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("email already in use") from exc

    def set_disabled(self, user_id: str, disabled: bool) -> None:
        """Disable (ending every session) or enable a user.

        Refuses with LastAdmin, in the same transaction as the write, when the
        user is the only enabled admin left.
        """
        with self._tx() as c:
            if disabled:
                self._guard_last_admin(c, user_id)
                c.execute("DELETE FROM auth_tokens WHERE user_id = ?", (user_id,))
            c.execute(
                "UPDATE users SET disabled = ? WHERE user_id = ?", (int(disabled), user_id)
            )

    def reset_password(self, user_id: str, password_hash: str) -> None:
        """An admin-issued temporary password: must change, every session ends."""
        with self._tx() as c:
            c.execute(
                "UPDATE users SET password_hash = ?, must_change = 1 WHERE user_id = ?",
                (password_hash, user_id),
            )
            c.execute("DELETE FROM auth_tokens WHERE user_id = ?", (user_id,))

    def change_password(
        self, user_id: str, password_hash: str, keep_token_hash: str
    ) -> None:
        """The user's own new password: clears must_change, ends every other session."""
        with self._tx() as c:
            c.execute(
                "UPDATE users SET password_hash = ?, must_change = 0 WHERE user_id = ?",
                (password_hash, user_id),
            )
            c.execute(
                "DELETE FROM auth_tokens WHERE user_id = ? AND token_hash != ?",
                (user_id, keep_token_hash),
            )

    # -- groups --------------------------------------------------------

    def _guard_last_admin(self, c: sqlite3.Connection, user_id: str) -> None:
        """Raise LastAdmin if removing user_id leaves no enabled admin.

        Called inside the caller's write transaction so the count and the
        write cannot be split by a concurrent change.
        """
        others = c.execute(
            "SELECT COUNT(*) FROM group_members m JOIN users u ON u.user_id = m.user_id "
            "WHERE m.group_name = ? AND u.disabled = 0 AND u.user_id != ?",
            (ADMINS, user_id),
        ).fetchone()[0]
        target_is_enabled_admin = c.execute(
            "SELECT 1 FROM group_members m JOIN users u ON u.user_id = m.user_id "
            "WHERE m.group_name = ? AND u.disabled = 0 AND u.user_id = ?",
            (ADMINS, user_id),
        ).fetchone()
        if target_is_enabled_admin and others == 0:
            raise LastAdmin("that would leave no enabled admin")

    def get_group(self, name: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT name FROM groups WHERE name = ?", (name,)
            ).fetchone()
        return _row_to_dict(row)

    def create_group(self, name: str) -> dict[str, Any]:
        try:
            with self._tx() as c:
                c.execute(
                    "INSERT INTO groups (name, created_at) VALUES (?, ?)", (name, _now())
                )
        except sqlite3.IntegrityError as exc:
            raise Conflict("group already exists") from exc
        return {"name": name, "members": []}

    def list_groups(self) -> list[dict[str, Any]]:
        with self._lock:
            groups = self._conn.execute(
                "SELECT name FROM groups ORDER BY name"
            ).fetchall()
            members = self._conn.execute(
                "SELECT m.group_name, u.username FROM group_members m "
                "JOIN users u ON u.user_id = m.user_id ORDER BY u.username"
            ).fetchall()
        by_group: dict[str, list[str]] = {g["name"].lower(): [] for g in groups}
        for m in members:
            by_group[m["group_name"].lower()].append(m["username"])
        return [{"name": g["name"], "members": by_group[g["name"].lower()]} for g in groups]

    def groups_for(self, user_id: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT g.name FROM group_members m JOIN groups g ON g.name = m.group_name "
                "WHERE m.user_id = ? ORDER BY g.name",
                (user_id,),
            ).fetchall()
        return [r["name"] for r in rows]

    def add_member(self, group_name: str, user_id: str) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT OR IGNORE INTO group_members (group_name, user_id) "
                "SELECT name, ? FROM groups WHERE name = ?",
                (user_id, group_name),
            )

    def remove_member(self, group_name: str, user_id: str) -> None:
        """Take a user out of a group; LastAdmin if it is the last enabled admin."""
        with self._tx() as c:
            group = c.execute(
                "SELECT name FROM groups WHERE name = ?", (group_name,)
            ).fetchone()
            if group is None:
                return
            if group["name"].lower() == ADMINS:
                self._guard_last_admin(c, user_id)
            c.execute(
                "DELETE FROM group_members WHERE group_name = ? AND user_id = ?",
                (group["name"], user_id),
            )

    # -- site grants ---------------------------------------------------

    def sites_for(self, user_id: str) -> list[str]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT site FROM site_grants WHERE user_id = ? ORDER BY site", (user_id,)
            ).fetchall()
        return [r["site"] for r in rows]

    def grant_site(self, user_id: str, site: str) -> None:
        with self._tx() as c:
            c.execute(
                "INSERT OR IGNORE INTO site_grants (user_id, site) VALUES (?, ?)",
                (user_id, site),
            )

    def revoke_site(self, user_id: str, site: str) -> None:
        with self._tx() as c:
            c.execute(
                "DELETE FROM site_grants WHERE user_id = ? AND site = ?", (user_id, site)
            )

    # -- user lookups --------------------------------------------------

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE user_id = ?", (user_id,)
            ).fetchone()
        return _row_to_dict(row)

    def user_by_username(self, username: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
            ).fetchone()
        return _row_to_dict(row)

    def set_password(self, user_id: str, password_hash: str) -> None:
        """A password the user chose through the emailed reset link."""
        with self._tx() as c:
            c.execute(
                "UPDATE users SET password_hash = ?, must_change = 0 WHERE user_id = ?",
                (password_hash, user_id),
            )

    # -- sessions --------------------------------------------------------

    def store_token(self, token_hash: str, user_id: str, ttl_hours: int) -> dict[str, Any]:
        created_at = _now()
        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
        ).isoformat()
        with self._tx() as c:
            c.execute(
                "INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) "
                "VALUES (?, ?, ?, ?)",
                (token_hash, user_id, created_at, expires_at),
            )
        return {"created_at": created_at, "expires_at": expires_at}

    def user_for_token(self, token_hash: str) -> dict[str, Any] | None:
        """The user a live token belongs to — None if expired or the user is disabled."""
        with self._lock:
            row = self._conn.execute(
                "SELECT user_id, expires_at FROM auth_tokens WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
        if row is None:
            return None
        if row["expires_at"] < _now():
            self.delete_token(token_hash)
            return None
        user = self.get_user(row["user_id"])
        if user is None or user["disabled"]:
            return None
        return user

    def delete_token(self, token_hash: str) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM auth_tokens WHERE token_hash = ?", (token_hash,))

    def delete_user_tokens(self, user_id: str) -> None:
        with self._tx() as c:
            c.execute("DELETE FROM auth_tokens WHERE user_id = ?", (user_id,))

    # -- password reset ----------------------------------------------------

    def store_reset_token(
        self, token_hash: str, user_id: str, ttl_minutes: int
    ) -> dict[str, Any]:
        created_at = _now()
        expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
        ).isoformat()
        with self._tx() as c:
            c.execute(
                "INSERT INTO password_reset_tokens "
                "(token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token_hash, user_id, created_at, expires_at),
            )
        return {"created_at": created_at, "expires_at": expires_at}

    def consume_reset_token(self, token_hash: str) -> str | None:
        """Validate, mark used, and return the owning user_id — or None."""
        with self._tx() as c:
            row = c.execute(
                "SELECT user_id, expires_at, used FROM password_reset_tokens "
                "WHERE token_hash = ?",
                (token_hash,),
            ).fetchone()
            if row is None or row["used"] or row["expires_at"] < _now():
                return None
            c.execute(
                "UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?",
                (token_hash,),
            )
            return row["user_id"]
