"""Bootstrap the one account this service exists to protect.

Runs at startup. Idempotent: does nothing once any user row exists, so the
seed credential in `.env` matters only for the very first launch against an
empty database and is inert afterward.
"""

from __future__ import annotations

import logging

import auth
import registry as registry_mod
from config import Settings

log = logging.getLogger("auth_service.seed")


def seed(reg: registry_mod.Registry, settings: Settings) -> None:
    if reg.count_users() > 0:
        return
    if not settings.seed_username or not settings.seed_password:
        log.warning(
            "no users exist and AUTH_SEED_USERNAME/AUTH_SEED_PASSWORD are unset — "
            "nobody can log in until an account is created"
        )
        return
    reg.create_user(
        settings.seed_username,
        auth.hash_password(settings.seed_password),
        email=settings.reset_notify_email,
    )
    log.info("seeded account %r from AUTH_SEED_USERNAME", settings.seed_username)
