# auth-service

Shared login for Daniel's personal sites (backlog, property lens, btc, apps,
the hive console). One FastAPI app, one sqlite db. Each site stays a thin
client: read the `auth_session` cookie off the incoming request, call
`GET /verify` to find out who it belongs to, redirect to login if it's
missing or invalid.

## Users, groups and sites

Membership of the `admins` group is the admin role. `GET /verify` with no
`site` admits admins only, so every site that does not name itself stays
the admins' alone however many users exist. `GET /verify?site=<name>` admits
admins and users granted that site. A disabled user is refused everywhere,
and disabling, an admin reset or a password change ends the user's sessions.
The last enabled admin cannot be disabled or taken out of `admins`. Users
are never deleted.

`/admin/*` manages users, groups and site grants behind the service bearer
`AUTH_SERVICE_ADMIN_TOKEN`. An admin-created user with a temporary password
must change it (`POST /password/change`) — `must_change` is reported on
`/login` and `/verify`, and the calling site enforces it. A user created
without a password cannot sign in by password at all.

On startup the db is brought up to the current schema in place; on a db
that predates groups the `admins` group is created with the account
`AUTH_SEED_USERNAME` names as its one member.

## Run

```
docker compose up -d --build
```

Runs as container `auth-service` on :8600 with the sqlite db bind-mounted
from `./db` so it survives rebuilds. The compose file sets
`AUTH_COOKIE_DOMAIN=sparktobloom.com` so the session cookie is shared
across every personal-site subdomain.

For local dev without Docker:

```
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env   # or edit the .env already here
.venv/bin/python server.py
```

`AUTH_SEED_USERNAME` / `AUTH_SEED_PASSWORD` in `.env` create the one account
on first launch against an empty database. Edit the password there before
the first run — after the account exists those vars are inert, change your
password via `/password/reset/request` + `/password/reset/confirm` instead.

Set `AUTH_COOKIE_DOMAIN` to the parent domain covering every personal site
(e.g. `.example.com`) so the session cookie is shared across subdomains.

## Endpoints

`POST /login`, `POST /logout`, `GET /verify[?site=]`, `POST /password/change`,
`POST /password/reset/request`, `POST /password/reset/confirm`, `GET /health`.

Admin: `POST|GET /admin/users`, `GET|PATCH /admin/users/{username}`,
`POST /admin/users/{username}/reset`, `PUT|DELETE
/admin/users/{username}/sites/{site}`, `GET|POST /admin/groups`,
`PUT|DELETE /admin/groups/{name}/members/{username}`.

## Test

```
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```
