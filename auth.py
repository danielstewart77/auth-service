"""Password hashing and bearer tokens.

Stdlib only. A password is stored as a scrypt digest, never reversibly; a
token is stored as its sha256, so a stolen database yields no usable
session. The plaintext token is returned exactly once, at login.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

# scrypt work factors. n=2**14 with r=8 costs ~16MB and a few tens of ms —
# enough to make an offline guess expensive without making login feel slow.
_N = 1 << 14
_R = 8
_P = 1
_DKLEN = 32
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """Encode a password as `scrypt$n$r$p$salt$digest`, all hex."""
    if not password:
        raise ValueError("password must not be empty")
    salt = secrets.token_bytes(_SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN
    )
    return f"scrypt${_N}${_R}${_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    """Constant-time check of a password against a stored digest."""
    try:
        scheme, n, r, p, salt_hex, digest_hex = encoded.split("$")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(bytes.fromhex(digest_hex)),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate.hex(), digest_hex)


def new_token() -> str:
    """A fresh opaque bearer token. Shown to the caller once and never stored."""
    return secrets.token_urlsafe(32)


def token_digest(token: str) -> str:
    """What the database holds in place of the token itself."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def bearer(header: str | None) -> str | None:
    """Pull the token out of an `Authorization: Bearer …` header."""
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()
