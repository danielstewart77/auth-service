# auth-service

Shared login for Daniel's personal sites (backlog, property lens, btc, apps,
and whatever comes next). One FastAPI app, one sqlite db, one account today.
Each site stays a thin client: read the `auth_session` cookie off the
incoming request, call `GET /verify` to find out who it belongs to, redirect
to login if it's missing or invalid.

## Run

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

`POST /login`, `POST /logout`, `GET /verify`, `POST /password/reset/request`,
`POST /password/reset/confirm`, `GET /health`.

## Test

```
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```
