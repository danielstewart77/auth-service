import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

ADMIN_TOKEN = "test-admin-token"  # secret-guard: allow (invented test value)


def _fresh_server(tmp_path, monkeypatch, admin_token: str):
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
    monkeypatch.setenv("AUTH_SERVICE_ADMIN_TOKEN", admin_token)

    for name in ("server", "config"):
        sys.modules.pop(name, None)
    return importlib.import_module("server")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    server = _fresh_server(tmp_path, monkeypatch, ADMIN_TOKEN)
    with TestClient(server.app) as c:
        yield c
    server.registry.close()
    sys.modules.pop("server", None)


@pytest.fixture()
def client_without_admin_token(tmp_path, monkeypatch):
    server = _fresh_server(tmp_path, monkeypatch, "")
    with TestClient(server.app) as c:
        yield c
    server.registry.close()
    sys.modules.pop("server", None)
