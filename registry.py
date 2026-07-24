"""SQLite persistence: users, live sessions, password-reset tokens."""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_SCHEMA_PATH = Path(__file__).resolve().parent / "db" / "schema.sql"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None


class Registry:
    def __init__(self, db_path: Path):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA_PATH.read_text(encoding="utf-8"))
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # -- users ---------------------------------------------------------

    def count_users(self) -> int:
        return self._conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def create_user(
        self, username: str, password_hash: str, email: str = ""
    ) -> dict[str, Any]:
        user_id = str(uuid.uuid4())
        self._conn.execute(
            "INSERT INTO users (user_id, username, email, password_hash, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (user_id, username, email, password_hash, _now()),
        )
        self._conn.commit()
        return self.get_user(user_id)

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ).fetchone()
        return _row_to_dict(row)

    def user_by_username(self, username: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM users WHERE username = ? COLLATE NOCASE", (username,)
        ).fetchone()
        return _row_to_dict(row)

    def set_password(self, user_id: str, password_hash: str) -> None:
        self._conn.execute(
            "UPDATE users SET password_hash = ? WHERE user_id = ?",
            (password_hash, user_id),
        )
        self._conn.commit()

    # -- sessions --------------------------------------------------------

    def store_token(self, token_hash: str, user_id: str, ttl_hours: int) -> dict[str, Any]:
        created_at = _now()
        expires_at = (
            datetime.now(timezone.utc) + timedelta(hours=ttl_hours)
        ).isoformat()
        self._conn.execute(
            "INSERT INTO auth_tokens (token_hash, user_id, created_at, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (token_hash, user_id, created_at, expires_at),
        )
        self._conn.commit()
        return {"created_at": created_at, "expires_at": expires_at}

    def user_for_token(self, token_hash: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT user_id, expires_at FROM auth_tokens WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None:
            return None
        if row["expires_at"] < _now():
            self.delete_token(token_hash)
            return None
        return self.get_user(row["user_id"])

    def delete_token(self, token_hash: str) -> None:
        self._conn.execute(
            "DELETE FROM auth_tokens WHERE token_hash = ?", (token_hash,)
        )
        self._conn.commit()

    def delete_user_tokens(self, user_id: str) -> None:
        self._conn.execute(
            "DELETE FROM auth_tokens WHERE user_id = ?", (user_id,)
        )
        self._conn.commit()

    # -- password reset ----------------------------------------------------

    def store_reset_token(
        self, token_hash: str, user_id: str, ttl_minutes: int
    ) -> dict[str, Any]:
        created_at = _now()
        expires_at = (
            datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
        ).isoformat()
        self._conn.execute(
            "INSERT INTO password_reset_tokens "
            "(token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token_hash, user_id, created_at, expires_at),
        )
        self._conn.commit()
        return {"created_at": created_at, "expires_at": expires_at}

    def consume_reset_token(self, token_hash: str) -> str | None:
        """Validate, mark used, and return the owning user_id — or None."""
        row = self._conn.execute(
            "SELECT user_id, expires_at, used FROM password_reset_tokens "
            "WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if row is None or row["used"] or row["expires_at"] < _now():
            return None
        self._conn.execute(
            "UPDATE password_reset_tokens SET used = 1 WHERE token_hash = ?",
            (token_hash,),
        )
        self._conn.commit()
        return row["user_id"]
