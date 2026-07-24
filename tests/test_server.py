SEED_USERNAME = "daniel"
SEED_PASSWORD = "correct horse battery staple"


def test_health(client):
    assert client.get("/health").json() == {"status": "ok"}


def test_login_with_seeded_account(client):
    resp = client.post("/login", json={"username": SEED_USERNAME, "password": SEED_PASSWORD})
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == SEED_USERNAME
    assert "auth_session" in resp.cookies


def test_login_rejects_bad_password(client):
    resp = client.post("/login", json={"username": SEED_USERNAME, "password": "wrong"})
    assert resp.status_code == 401


def test_login_rejects_unknown_username(client):
    resp = client.post("/login", json={"username": "nobody", "password": "irrelevant"})
    assert resp.status_code == 401


def test_verify_with_valid_cookie(client):
    client.post("/login", json={"username": SEED_USERNAME, "password": SEED_PASSWORD})
    resp = client.get("/verify")
    assert resp.status_code == 200
    assert resp.json()["username"] == SEED_USERNAME


def test_verify_without_cookie_is_401(client):
    resp = client.get("/verify")
    assert resp.status_code == 401


def test_verify_with_bearer_token(client):
    login = client.post("/login", json={"username": SEED_USERNAME, "password": SEED_PASSWORD})
    token = login.json()["token"]
    resp = client.get("/verify", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200


def test_logout_invalidates_session(client):
    client.post("/login", json={"username": SEED_USERNAME, "password": SEED_PASSWORD})
    assert client.get("/verify").status_code == 200
    client.post("/logout")
    assert client.get("/verify").status_code == 401


def test_password_reset_request_is_not_a_username_oracle(client):
    real = client.post("/password/reset/request", json={"username": SEED_USERNAME})
    fake = client.post("/password/reset/request", json={"username": "nobody-at-all"})
    assert real.status_code == fake.status_code == 202


def test_reset_confirm_rejects_bad_token(client):
    resp = client.post(
        "/password/reset/confirm", json={"token": "not-a-real-token", "new_password": "new-pw"}
    )
    assert resp.status_code == 400


def test_reset_confirm_changes_password_and_kills_sessions(client):
    import auth
    import server as server_mod

    user = server_mod.registry.user_by_username(SEED_USERNAME)
    token = auth.new_token()
    server_mod.registry.store_reset_token(auth.token_digest(token), user["user_id"], ttl_minutes=30)

    client.post("/login", json={"username": SEED_USERNAME, "password": SEED_PASSWORD})
    assert client.get("/verify").status_code == 200

    resp = client.post(
        "/password/reset/confirm", json={"token": token, "new_password": "brand-new-password"}
    )
    assert resp.status_code == 204

    # old session is dead
    assert client.get("/verify").status_code == 401

    # new password works
    login = client.post(
        "/login", json={"username": SEED_USERNAME, "password": "brand-new-password"}
    )
    assert login.status_code == 200
