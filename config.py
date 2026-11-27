"""Non-secret settings, resolved from the environment with sane defaults.

Every value that differs between a dev box and a live deployment is an env
var, so going live is a `.env` edit rather than a code change.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Settings:
    host: str = field(default_factory=lambda: os.getenv("AUTH_HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("AUTH_PORT", "8600")))

    db_path: Path = field(
        default_factory=lambda: Path(os.getenv("AUTH_DB", str(ROOT / "db" / "auth.db")))
    )

    # The cookie is set on this domain so every subdomain (backlog, property
    # lens, btc, ...) shares one login. Empty means host-only (fine for local
    # dev where every site runs on 127.0.0.1 with a different port).
    cookie_domain: str = field(default_factory=lambda: os.getenv("AUTH_COOKIE_DOMAIN", ""))
    cookie_secure: bool = field(
        default_factory=lambda: os.getenv("AUTH_COOKIE_SECURE", "true").strip().lower()
        in {"1", "true", "yes", "on"}
    )
    auth_token_ttl_hours: int = field(
        default_factory=lambda: int(os.getenv("AUTH_TOKEN_TTL_HOURS", "720"))
    )
    reset_token_ttl_minutes: int = field(
        default_factory=lambda: int(os.getenv("AUTH_RESET_TOKEN_TTL_MINUTES", "30"))
    )

    # One-time bootstrap credential. Consumed on first startup to create the
    # single account this service exists to protect, then the account row is
    # what matters and these are inert. See seed.py.
    seed_username: str = field(default_factory=lambda: os.getenv("AUTH_SEED_USERNAME", ""))
    seed_password: str = field(default_factory=lambda: os.getenv("AUTH_SEED_PASSWORD", ""))

    # Password-reset delivery. Left unset in local dev — the request endpoint
    # then logs the token server-side instead of emailing it.
    smtp_host: str = field(default_factory=lambda: os.getenv("SMTP_HOST", ""))
    smtp_port: int = field(default_factory=lambda: int(os.getenv("SMTP_PORT", "587")))
    smtp_user: str = field(default_factory=lambda: os.getenv("SMTP_USER", ""))
    smtp_password: str = field(default_factory=lambda: os.getenv("SMTP_PASSWORD", ""))
    smtp_from: str = field(default_factory=lambda: os.getenv("SMTP_FROM", ""))
    reset_notify_email: str = field(default_factory=lambda: os.getenv("AUTH_RESET_EMAIL", ""))
    reset_link_base: str = field(
        default_factory=lambda: os.getenv("AUTH_RESET_LINK_BASE", "http://127.0.0.1:8600")
    )

    debug: bool = field(
        default_factory=lambda: os.getenv("AUTH_DEBUG", "false").strip().lower()
        in {"1", "true", "yes", "on"}
    )


def load_dotenv(path: Path | None = None) -> None:
    """Fold `.env` into os.environ. Real env vars always win."""
    path = path or ROOT / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


def load() -> Settings:
    """Read settings fresh from the environment, with `.env` as the base layer."""
    load_dotenv()
    return Settings()
