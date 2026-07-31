"""auth-service: shared login for Daniel's personal sites.

One FastAPI app, one sqlite db, one account (today). A site sets no state of
its own: it reads the `auth_session` cookie off the incoming request and
calls GET /verify to find out who it belongs to.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

import auth
import mail
import registry as registry_mod
import seed as seed_mod
from config import load

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("auth_service")

AUTH_COOKIE = "auth_session"

settings = load()
registry = registry_mod.Registry(settings.db_path)
seed_mod.seed(registry, settings)

app = FastAPI(title="auth-service", docs_url=None, redoc_url=None, openapi_url=None)


class Login(BaseModel):
    username: str
    password: str


class ResetRequest(BaseModel):
    username: str


class ResetConfirm(BaseModel):
    token: str
    new_password: str


def _presented(request: Request) -> str | None:
    token = auth.bearer(request.headers.get("authorization"))
    if token:
        return token
    return request.cookies.get(AUTH_COOKIE)


def _current_user(request: Request) -> dict | None:
    token = _presented(request)
    if not token:
        return None
    return registry.user_for_token(auth.token_digest(token))


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        AUTH_COOKIE,
        token,
        max_age=settings.auth_token_ttl_hours * 3600,
        httponly=True,
        samesite="lax",
        secure=settings.cookie_secure,
        domain=settings.cookie_domain or None,
        path="/",
    )


@app.post("/login")
def login(body: Login, response: Response) -> dict:
    user = registry.user_by_username(body.username.strip())
    # Hash-compare even on a miss, so a wrong username and a wrong password
    # take the same time and the endpoint is not a username oracle.
    stored = user["password_hash"] if user else auth.hash_password("_")
    if not user or not auth.verify_password(body.password, stored):
        raise HTTPException(401, "bad username or password")
    if user["disabled"]:
        raise HTTPException(403, "account disabled")
    token = auth.new_token()
    issued = registry.store_token(
        auth.token_digest(token), user["user_id"], settings.auth_token_ttl_hours
    )
    _set_session_cookie(response, token)
    return {
        "token": token,
        "user_id": user["user_id"],
        "username": user["username"],
        "expires_at": issued["expires_at"],
    }


@app.post("/logout", status_code=204)
def logout(request: Request, response: Response) -> Response:
    token = _presented(request)
    if token:
        registry.delete_token(auth.token_digest(token))
    response = Response(status_code=204)
    response.delete_cookie(AUTH_COOKIE, domain=settings.cookie_domain or None, path="/")
    return response


@app.get("/verify")
def verify(request: Request) -> dict:
    """What every personal site calls to check the incoming cookie/token."""
    user = _current_user(request)
    if not user:
        raise HTTPException(401, "not authenticated")
    return {"user_id": user["user_id"], "username": user["username"]}


@app.post("/password/reset/request", status_code=202)
def request_reset(body: ResetRequest) -> Response:
    """Always 202, whether or not the username exists — no oracle."""
    user = registry.user_by_username(body.username.strip())
    if user and not user["disabled"]:
        token = auth.new_token()
        registry.store_reset_token(
            auth.token_digest(token), user["user_id"], settings.reset_token_ttl_minutes
        )
        link = f"{settings.reset_link_base}/password/reset?token={token}"
        to_email = user["email"] or settings.reset_notify_email
        if to_email:
            mail.send_reset_email(settings, to_email, link)
        else:
            log.warning("reset requested for %r but no email on file", user["username"])
    return Response(status_code=202)


@app.post("/password/reset/confirm", status_code=204)
def confirm_reset(body: ResetConfirm) -> Response:
    user_id = registry.consume_reset_token(auth.token_digest(body.token))
    if not user_id:
        raise HTTPException(400, "invalid or expired token")
    registry.set_password(user_id, auth.hash_password(body.new_password))
    registry.delete_user_tokens(user_id)
    return Response(status_code=204)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port)
