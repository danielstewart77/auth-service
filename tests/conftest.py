import importlib
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture()
def client(tmp_path, monkeypatch):
    """A TestClient wired to a fresh db and a freshly-imported server module.

    server.py builds its Registry and runs the seed at import time, so each
    test needs its own module instance pointed at its own throwaway db.
    """
    monkeypatch.setenv("AUTH_DB", str(tmp_path / "auth.db"))
    monkeypatch.setenv("AUTH_COOKIE_SECURE", "false")
    monkeypatch.setenv("AUTH_COOKIE_DOMAIN", "")
    monkeypatch.setenv("AUTH_SEED_USERNAME", "daniel")
    monkeypatch.setenv("AUTH_SEED_PASSWORD", "correct horse battery staple")
    monkeypatch.setenv("AUTH_RESET_EMAIL", "")
    monkeypatch.setenv("SMTP_HOST", "")

    for name in ("server", "config"):
        sys.modules.pop(name, None)
    server = importlib.import_module("server")

    with TestClient(server.app) as c:
        yield c

    server.registry.close()
    sys.modules.pop("server", None)
