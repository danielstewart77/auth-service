"""auth-service: shared login for Daniel's personal sites and the hive.

One FastAPI app, one sqlite db. A site sets no state of its own: it reads the
`auth_session` cookie off the incoming request and calls GET /verify to find
out who it belongs to. A site that names itself (`/verify?site=hive`) admits
the users granted it; a site that does not admits admins only, so adding a
user here lets nobody new into a site that never asked for one.

Users, groups and site grants are managed through /admin, behind an administrator's own
sign-in; no shared service token exists. Users are never deleted, only disabled.
"""

from __future__ import annotations

import logging

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from pydantic import BaseModel

import auth
import mail
import registry as registry_mod
import seed as seed_mod
from config import load

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("auth_service")

AUTH_COOKIE = "auth_session"

# What a login with no stored password is compared against, so a miss costs
# the same scrypt as a hit.
_MISS_HASH = auth.hash_password("_")

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


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class NewUser(BaseModel):
    username: str
    email: str | None = None
    temp_password: str | None = None
    sites: list[str] = []


class UserPatch(BaseModel):
    email: str | None = None
    disabled: bool | None = None


class TempPassword(BaseModel):
    temp_password: str


class NewGroup(BaseModel):
    name: str


def _presented(request: Request) -> str | None:
    token = auth.bearer(request.headers.get("authorization"))
    if token:
        return token
    return request.cookies.get(AUTH_COOKIE)


def _current_user(request: Request) -> dict | None:
    """The live, enabled user behind the presented token, or None."""
    token = _presented(request)
    if not token:
        return None
    return registry.user_for_token(auth.token_digest(token))


def _user_view(user: dict) -> dict:
    """The shape every /admin route returns a user in."""
    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"] or None,
        "must_change": bool(user["must_change"]),
        "disabled": bool(user["disabled"]),
        "groups": registry.groups_for(user["user_id"]),
        "sites": registry.sites_for(user["user_id"]),
    }


def _require_admin(request: Request) -> None:
    """Gate for every /admin route: a signed-in member of `admins`, by their own
    session (a bearer or the cookie). No shared service key is accepted. A
    signed-in person who is not an administrator is refused with 403; anyone
    else, including a caller presenting any other bearer, with 401."""
    user = _current_user(request)
    if not user:
        raise HTTPException(401, "admin sign-in required")
    groups = registry.groups_for(user["user_id"])
    if registry_mod.ADMINS not in (g.lower() for g in groups):
        raise HTTPException(403, "admins only")


def _user_or_404(username: str) -> dict:
    user = registry.user_by_username(username.strip())
    if not user:
        raise HTTPException(404, "no such user")
    return user


def _group_or_404(name: str) -> dict:
    group = registry.get_group(name.strip())
    if not group:
        raise HTTPException(404, "no such group")
    return group


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
    # A user with no password (created for Microsoft/Windows sign-in) is a
    # miss here, the same as an unknown name.
    stored = user["password_hash"] if user else None
    matched = auth.verify_password(body.password, stored or _MISS_HASH)
    if not stored or not matched:
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
        "must_change": bool(user["must_change"]),
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
def verify(request: Request, site: str | None = None) -> dict:
    """What every site calls to check the incoming cookie/token.

    401: no token, an expired one, or a disabled user. With `site`, 403 for a
    user granted neither that site nor membership of `admins`. Without it,
    403 for anyone not in `admins` — every site that predates site grants
    stays the admins' alone. Nothing here is cached: a disable or a group
    change takes effect on the very next call.
    """
    user = _current_user(request)
    if not user:
        raise HTTPException(401, "not authenticated")
    groups = registry.groups_for(user["user_id"])
    is_admin = registry_mod.ADMINS in (g.lower() for g in groups)
    if not is_admin:
        if site is None:
            raise HTTPException(403, "admins only")
        if site.strip().lower() not in (s.lower() for s in registry.sites_for(user["user_id"])):
            raise HTTPException(403, "not granted this site")
    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "email": user["email"] or None,
        "must_change": bool(user["must_change"]),
        "groups": groups,
    }


@app.post("/password/change", status_code=204)
def change_password(body: PasswordChange, request: Request) -> Response:
    """The signed-in user sets their own password; ends their other sessions."""
    token = _presented(request)
    user = _current_user(request)
    if not token or not user:
        raise HTTPException(401, "not authenticated")
    if not user["password_hash"] or not auth.verify_password(
        body.current_password, user["password_hash"]
    ):
        raise HTTPException(403, "current password is wrong")
    if not body.new_password:
        raise HTTPException(400, "new password must not be empty")
    if body.new_password == body.current_password:
        raise HTTPException(400, "new password must differ from the current one")
    registry.change_password(
        user["user_id"], auth.hash_password(body.new_password), auth.token_digest(token)
    )
    return Response(status_code=204)


@app.post("/password/reset/request", status_code=202)
def request_reset(body: ResetRequest) -> Response:
    """Always 202, whether or not the username exists — no oracle."""
    user = registry.user_by_username(body.username.strip())
    # No reset for an account with no password: it signs in another way, and
    # a reset link would hand it a password it was created without.
    if user and not user["disabled"] and user["password_hash"]:
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


# -- admin API (service bearer) ------------------------------------------------

admin = [Depends(_require_admin)]


@app.post("/admin/users", status_code=201, dependencies=admin)
def admin_create_user(body: NewUser) -> dict:
    """A temp password means must change on first sign-in; none means no
    password sign-in at all (an account for Microsoft/Windows sign-in).
    `sites` are granted in the same write, so a created user is never left
    without the grant the caller asked for."""
    username = body.username.strip().lower()
    if not username:
        raise HTTPException(400, "username must not be empty")
    if body.temp_password is not None and not body.temp_password:
        raise HTTPException(400, "temp_password must not be empty")
    sites = [site.strip().lower() for site in body.sites]
    if not all(sites):
        raise HTTPException(400, "a site must not be empty")
    password_hash = auth.hash_password(body.temp_password) if body.temp_password else None
    try:
        user = registry.create_user(
            username,
            password_hash,
            email=(body.email or "").strip(),
            must_change=password_hash is not None,
            sites=sites,
        )
    except registry_mod.Conflict as exc:
        raise HTTPException(409, str(exc)) from exc
    return _user_view(user)


@app.get("/admin/users", dependencies=admin)
def admin_list_users() -> list[dict]:
    return [_user_view(u) for u in registry.list_users()]


@app.get("/admin/users/{username}", dependencies=admin)
def admin_get_user(username: str) -> dict:
    return _user_view(_user_or_404(username))


@app.patch("/admin/users/{username}", dependencies=admin)
def admin_patch_user(username: str, body: UserPatch) -> dict:
    user = _user_or_404(username)
    try:
        if body.email is not None:
            registry.set_email(user["user_id"], body.email.strip())
        if body.disabled is not None:
            registry.set_disabled(user["user_id"], body.disabled)
    except registry_mod.Conflict as exc:
        raise HTTPException(409, str(exc)) from exc
    return _user_view(registry.get_user(user["user_id"]))


@app.post("/admin/users/{username}/reset", dependencies=admin)
def admin_reset_user(username: str, body: TempPassword) -> dict:
    user = _user_or_404(username)
    if not body.temp_password:
        raise HTTPException(400, "temp_password must not be empty")
    registry.reset_password(user["user_id"], auth.hash_password(body.temp_password))
    return _user_view(registry.get_user(user["user_id"]))


@app.put("/admin/users/{username}/sites/{site}", status_code=204, dependencies=admin)
def admin_grant_site(username: str, site: str) -> Response:
    user = _user_or_404(username)
    registry.grant_site(user["user_id"], site.strip().lower())
    return Response(status_code=204)


@app.delete("/admin/users/{username}/sites/{site}", status_code=204, dependencies=admin)
def admin_revoke_site(username: str, site: str) -> Response:
    user = _user_or_404(username)
    registry.revoke_site(user["user_id"], site.strip().lower())
    return Response(status_code=204)


@app.get("/admin/groups", dependencies=admin)
def admin_list_groups() -> list[dict]:
    return registry.list_groups()


@app.post("/admin/groups", status_code=201, dependencies=admin)
def admin_create_group(body: NewGroup) -> dict:
    name = body.name.strip().lower()
    if not name:
        raise HTTPException(400, "group name must not be empty")
    try:
        return registry.create_group(name)
    except registry_mod.Conflict as exc:
        raise HTTPException(409, str(exc)) from exc


@app.put("/admin/groups/{name}/members/{username}", status_code=204, dependencies=admin)
def admin_add_member(name: str, username: str) -> Response:
    group = _group_or_404(name)
    user = _user_or_404(username)
    registry.add_member(group["name"], user["user_id"])
    return Response(status_code=204)


@app.delete("/admin/groups/{name}/members/{username}", status_code=204, dependencies=admin)
def admin_remove_member(name: str, username: str) -> Response:
    group = _group_or_404(name)
    user = _user_or_404(username)
    try:
        registry.remove_member(group["name"], user["user_id"])
    except registry_mod.LastAdmin as exc:
        raise HTTPException(409, str(exc)) from exc
    return Response(status_code=204)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=settings.host, port=settings.port)
