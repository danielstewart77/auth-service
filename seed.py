"""Bootstrap the first account and the `admins` group it belongs to.

Runs at startup. Idempotent: the account is created only against an empty
database, so the seed credential in `.env` matters only for the very first
launch and is inert afterward. The `admins` group is created once; on a
database that predates groups, the account AUTH_SEED_USERNAME names joins it
then (see Registry.ensure_admins_group).
"""

from __future__ import annotations

import logging

import auth
import registry as registry_mod
from config import Settings

log = logging.getLogger("auth_service.seed")


def seed(reg: registry_mod.Registry, settings: Settings) -> None:
    if reg.ensure_admins_group(settings.seed_username):
        log.info("created the %r group", registry_mod.ADMINS)
    if reg.count_users() > 0:
        return
    if not settings.seed_username or not settings.seed_password:
        log.warning(
            "no users exist and AUTH_SEED_USERNAME/AUTH_SEED_PASSWORD are unset — "
            "nobody can log in until an account is created"
        )
        return
    user = reg.create_user(
        settings.seed_username.strip().lower(),
        auth.hash_password(settings.seed_password),
        email=settings.reset_notify_email,
    )
    reg.add_member(registry_mod.ADMINS, user["user_id"])
    log.info("seeded admin account %r from AUTH_SEED_USERNAME", user["username"])
