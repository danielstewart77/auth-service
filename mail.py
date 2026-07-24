"""Password-reset email delivery. stdlib smtplib only.

Real reset flows need cross-device delivery. Left unconfigured in dev on
purpose — see `send_reset_email`'s fallback.
"""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

from config import Settings

log = logging.getLogger("auth_service.mail")


def send_reset_email(settings: Settings, to_email: str, reset_link: str) -> None:
    """Email the reset link, or log it if SMTP isn't configured.

    The logged fallback is deliberate for local/dev use — it must never be
    returned in an API response, since that would turn the reset endpoint
    into a username-existence oracle plus a free token handout.
    """
    if not settings.smtp_host:
        log.warning("SMTP not configured — reset link for %s: %s", to_email, reset_link)
        return

    message = EmailMessage()
    message["Subject"] = "Password reset"
    message["From"] = settings.smtp_from or settings.smtp_user
    message["To"] = to_email
    message.set_content(
        f"A password reset was requested for your account.\n\n"
        f"Reset link (valid {settings.reset_token_ttl_minutes} minutes):\n{reset_link}\n\n"
        f"If you didn't request this, ignore this email."
    )

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as smtp:
        smtp.starttls()
        if settings.smtp_user:
            smtp.login(settings.smtp_user, settings.smtp_password)
        smtp.send_message(message)
