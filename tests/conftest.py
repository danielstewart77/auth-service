import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# The signed-in administrator's bearer, refreshed in place by the `client`
# fixture (a new db and a new session every test). There is no service token.
ADMIN: dict = {}
SEED_ADMIN = ("daniel", "correct horse battery staple")


def _fresh_server(tmp_path, monkeypatch):
    """A freshly-imported server module pointed at its own throwaway db.

    server.py builds its Registry and runs the seed at import time, so each
    test needs its own module instance.
    """
    monkeypatch.setenv("AUTH_DB", str(tmp_path / "auth.db"))
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("AUTH_COOKIE_DOMAIN", "")
    monkeypatch.setenv("AUTH_SEED_USERNAME", "daniel")
    monkeypatch.setenv("AUTH_SEED_PASSWORD", "correct horse battery staple")
    monkeypatch.setenv("AUTH_RESET_EMAIL", "")
    monkeypatch.setenv("SMTP_HOST", "")
    monkeypatch.delenv("AUTH_SERVICE_ADMIN_TOKEN", raising=False)

    for name in ("server", "config"):
        sys.modules.pop(name, None)
    return importlib.import_module("server")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    server = _fresh_server(tmp_path, monkeypatch)
    with TestClient(server.app) as c:
        resp = c.post("/login", json={"username": SEED_ADMIN[0], "password": SEED_ADMIN[1]})
        assert resp.status_code == 200
        ADMIN.clear()
        ADMIN["Authorization"] = f"Bearer {resp.json()['token']}"
        c.cookies.clear()
        yield c
    server.registry.close()
    sys.modules.pop("server", None)
