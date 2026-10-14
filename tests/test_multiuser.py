"""Users, groups, site grants and the admin API (multi-user hive, wave one)."""

from conftest import ADMIN_TOKEN

SEED_USERNAME = "daniel"
SEED_PASSWORD = "correct horse battery staple"
ADMIN = {"Authorization": f"Bearer {ADMIN_TOKEN}"}


def _login(client, username, password):
    """Log in and hand back the response, leaving no cookie in the jar.

    Every later call names its token explicitly, so one test can hold several
    users' sessions at once without the client's cookie jar choosing for it.
    """
    resp = client.post("/login", json={"username": username, "password": password})
    client.cookies.clear()
    return resp


def _token(client, username, password):
    resp = _login(client, username, password)
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


def _create(client, username, temp_password="temp-pw-1", email=None):
    body = {"username": username, "temp_password": temp_password}
    if email is not None:
        body["email"] = email
    resp = client.post("/admin/users", json=body, headers=ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _change(client, token, current, new):
    return client.post(
        "/password/change",
        json={"current_password": current, "new_password": new},
        headers=_bearer(token),
    )


# -- creating users and the first sign-in -----------------------------------


def test_created_user_signs_in_with_temp_password_flagged_must_change(client):
    user = _create(client, "Sloan", email="sloan@example.com")
    assert user["username"] == "sloan"
    assert user["must_change"] is True
    assert user["disabled"] is False
    assert user["groups"] == []
    assert user["sites"] == []

    resp = _login(client, "sloan", "temp-pw-1")
    assert resp.status_code == 200
    assert resp.json()["must_change"] is True
    verify = client.get(
        "/verify", params={"site": "hive"}, headers=_bearer(resp.json()["token"])
    )
    # No grant yet, but the token itself is live: 403, not 401.
    assert verify.status_code == 403


def test_password_change_clears_must_change_and_retires_old_password(client):
    _create(client, "sloan")
    client.put("/admin/users/sloan/sites/hive", headers=ADMIN)
    token = _token(client, "sloan", "temp-pw-1")

    assert _change(client, token, "temp-pw-1", "sloans-own-pw").status_code == 204

    verify = client.get("/verify", params={"site": "hive"}, headers=_bearer(token))
    assert verify.status_code == 200
    assert verify.json()["must_change"] is False
    assert _login(client, "sloan", "temp-pw-1").status_code == 401
    fresh = _login(client, "sloan", "sloans-own-pw")
    assert fresh.status_code == 200
    assert fresh.json()["must_change"] is False


def test_password_change_ends_every_other_session_but_the_callers(client):
    _create(client, "sloan")
    client.put("/admin/users/sloan/sites/hive", headers=ADMIN)
    caller = _token(client, "sloan", "temp-pw-1")
    other = _token(client, "sloan", "temp-pw-1")

    assert _change(client, caller, "temp-pw-1", "sloans-own-pw").status_code == 204

    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(other)).status_code == 401
    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(caller)).status_code == 200


def test_password_change_refuses_wrong_current_password_and_no_session(client):
    _create(client, "sloan")
    token = _token(client, "sloan", "temp-pw-1")
    assert _change(client, token, "not-it", "sloans-own-pw").status_code == 403
    assert _login(client, "sloan", "temp-pw-1").status_code == 200

    anon = client.post(
        "/password/change",
        json={"current_password": "temp-pw-1", "new_password": "x-y-z"},
    )
    assert anon.status_code == 401


def test_password_change_refuses_keeping_the_temp_password(client):
    _create(client, "sloan")
    token = _token(client, "sloan", "temp-pw-1")
    assert _change(client, token, "temp-pw-1", "temp-pw-1").status_code == 400
    assert _login(client, "sloan", "temp-pw-1").json()["must_change"] is True


def test_password_change_works_from_the_cookie(client):
    _create(client, "sloan")
    client.post("/login", json={"username": "sloan", "password": "temp-pw-1"})
    resp = client.post(
        "/password/change",
        json={"current_password": "temp-pw-1", "new_password": "sloans-own-pw"},
    )
    assert resp.status_code == 204


def test_user_created_without_password_cannot_sign_in_by_password(client):
    resp = client.post(
        "/admin/users", json={"username": "aiden", "email": "aiden@example.com"}, headers=ADMIN
    )
    assert resp.status_code == 201
    assert resp.json()["must_change"] is False
    assert _login(client, "aiden", "").status_code in (401, 422)
    assert _login(client, "aiden", "anything").status_code == 401


def test_duplicate_username_or_email_is_409_case_insensitively(client):
    _create(client, "sloan", email="Sloan@Example.com")
    dup_name = client.post(
        "/admin/users", json={"username": "SLOAN", "temp_password": "x1"}, headers=ADMIN
    )
    dup_email = client.post(
        "/admin/users",
        json={"username": "other", "email": "sloan@example.COM", "temp_password": "x1"},
        headers=ADMIN,
    )
    assert dup_name.status_code == 409
    assert dup_email.status_code == 409


def test_get_user_and_listing(client):
    _create(client, "sloan")
    one = client.get("/admin/users/Sloan", headers=ADMIN)
    assert one.status_code == 200
    assert one.json()["username"] == "sloan"
    assert client.get("/admin/users/nobody", headers=ADMIN).status_code == 404
    names = {u["username"] for u in client.get("/admin/users", headers=ADMIN).json()}
    assert names == {"daniel", "sloan"}
    daniel = client.get("/admin/users/daniel", headers=ADMIN).json()
    assert daniel["groups"] == ["admins"]
    assert set(daniel) >= {"user_id", "username", "email", "must_change", "disabled", "groups", "sites"}


def test_patch_email_changes_it_and_refuses_a_taken_one(client):
    _create(client, "sloan", email="sloan@example.com")
    _create(client, "aiden", email="aiden@example.com")
    ok = client.patch("/admin/users/sloan", json={"email": "s2@example.com"}, headers=ADMIN)
    assert ok.status_code == 200
    assert ok.json()["email"] == "s2@example.com"
    taken = client.patch("/admin/users/sloan", json={"email": "AIDEN@example.com"}, headers=ADMIN)
    assert taken.status_code == 409


# -- T3: disabled users ------------------------------------------------------


def test_disabled_user_is_refused_sign_in_and_live_session_ends_at_once(client):
    _create(client, "sloan")
    client.put("/admin/users/sloan/sites/hive", headers=ADMIN)
    token = _token(client, "sloan", "temp-pw-1")
    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(token)).status_code == 200

    resp = client.patch("/admin/users/sloan", json={"disabled": True}, headers=ADMIN)
    assert resp.status_code == 200
    assert resp.json()["disabled"] is True

    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(token)).status_code == 401
    assert _login(client, "sloan", "temp-pw-1").status_code == 403


def test_reenabled_user_signs_in_again(client):
    _create(client, "sloan")
    client.patch("/admin/users/sloan", json={"disabled": True}, headers=ADMIN)
    assert client.patch("/admin/users/sloan", json={"disabled": False}, headers=ADMIN).json()["disabled"] is False
    assert _login(client, "sloan", "temp-pw-1").status_code == 200


def test_disabled_user_with_a_token_is_refused_by_verify(client):
    """A token that survived the disable (written straight to the db) still fails."""
    import auth
    import server as server_mod

    _create(client, "sloan")
    client.put("/admin/users/sloan/sites/hive", headers=ADMIN)
    client.patch("/admin/users/sloan", json={"disabled": True}, headers=ADMIN)
    user = server_mod.registry.user_by_username("sloan")
    token = auth.new_token()
    server_mod.registry.store_token(auth.token_digest(token), user["user_id"], ttl_hours=1)
    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(token)).status_code == 401
    assert _change(client, token, "temp-pw-1", "new-pw-9").status_code == 401


# -- T4 / reset ----------------------------------------------------------------


def test_admin_reset_issues_new_temp_password_and_ends_sessions(client):
    _create(client, "sloan")
    client.put("/admin/users/sloan/sites/hive", headers=ADMIN)
    token = _token(client, "sloan", "temp-pw-1")
    _change(client, token, "temp-pw-1", "sloans-own-pw")

    resp = client.post("/admin/users/sloan/reset", json={"temp_password": "temp-pw-2"}, headers=ADMIN)
    assert resp.status_code == 200
    assert resp.json()["must_change"] is True

    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(token)).status_code == 401
    assert _login(client, "sloan", "sloans-own-pw").status_code == 401
    again = _login(client, "sloan", "temp-pw-2")
    assert again.status_code == 200
    assert again.json()["must_change"] is True
    unknown = client.post("/admin/users/nobody/reset", json={"temp_password": "x1"}, headers=ADMIN)
    assert unknown.status_code == 404


# -- T5: the admin API is behind the service token -----------------------------


ADMIN_CALLS = [
    ("get", "/admin/users", None),
    ("post", "/admin/users", {"username": "sloan", "temp_password": "x1"}),
    ("get", "/admin/users/daniel", None),
    ("patch", "/admin/users/daniel", {"disabled": True}),
    ("post", "/admin/users/daniel/reset", {"temp_password": "x1"}),
    ("get", "/admin/groups", None),
    ("post", "/admin/groups", {"name": "kids"}),
    ("put", "/admin/groups/admins/members/daniel", None),
    ("delete", "/admin/groups/admins/members/daniel", None),
    ("put", "/admin/users/daniel/sites/hive", None),
    ("delete", "/admin/users/daniel/sites/hive", None),
]


def _call(client, method, path, body, headers):
    kwargs = {"headers": headers}
    if body is not None:
        kwargs["json"] = body
    return client.request(method.upper(), path, **kwargs)


def test_admin_routes_refuse_missing_wrong_or_user_credentials(client):
    _create(client, "sloan")
    sloan = _token(client, "sloan", "temp-pw-1")
    daniel = _token(client, SEED_USERNAME, SEED_PASSWORD)
    for method, path, body in ADMIN_CALLS:
        for headers in ({}, {"Authorization": "Bearer wrong"}, _bearer(sloan), _bearer(daniel)):
            resp = _call(client, method, path, body, headers)
            assert resp.status_code == 401, (method, path, headers, resp.status_code)
    # None of them took effect.
    assert _login(client, SEED_USERNAME, SEED_PASSWORD).status_code == 200


def test_admin_routes_are_503_when_no_admin_token_is_configured(client_without_admin_token):
    for method, path, body in ADMIN_CALLS:
        resp = _call(client_without_admin_token, method, path, body, {"Authorization": "Bearer "})
        assert resp.status_code == 503, (method, path)
        resp = _call(client_without_admin_token, method, path, body, {"Authorization": "Bearer x"})
        assert resp.status_code == 503, (method, path)


# -- T6 / T13: admins and sites at /verify --------------------------------------


def test_verify_without_site_admits_only_admins(client):
    _create(client, "sloan")
    sloan = _token(client, "sloan", "temp-pw-1")
    daniel = _token(client, SEED_USERNAME, SEED_PASSWORD)

    assert client.get("/verify", headers=_bearer(sloan)).status_code == 403
    resp = client.get("/verify", headers=_bearer(daniel))
    assert resp.status_code == 200
    body = resp.json()
    assert body["username"] == SEED_USERNAME
    assert body["groups"] == ["admins"]
    assert body["must_change"] is False
    assert set(body) >= {"user_id", "username", "email", "must_change", "groups"}


def test_verify_with_site_admits_granted_and_refuses_ungranted(client):
    _create(client, "sloan")
    _create(client, "aiden")
    assert client.put("/admin/users/sloan/sites/hive", headers=ADMIN).status_code == 204
    sloan = _token(client, "sloan", "temp-pw-1")
    aiden = _token(client, "aiden", "temp-pw-1")

    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(sloan)).status_code == 200
    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(aiden)).status_code == 403
    assert client.get("/verify", params={"site": "btc"}, headers=_bearer(sloan)).status_code == 403
    assert client.get("/admin/users/sloan", headers=ADMIN).json()["sites"] == ["hive"]

    assert client.delete("/admin/users/sloan/sites/hive", headers=ADMIN).status_code == 204
    assert client.get("/verify", params={"site": "hive"}, headers=_bearer(sloan)).status_code == 403


def test_joining_admins_makes_admin_on_next_request_and_leaving_takes_it(client):
    _create(client, "sloan")
    sloan = _token(client, "sloan", "temp-pw-1")
    assert client.get("/verify", headers=_bearer(sloan)).status_code == 403

    assert client.put("/admin/groups/admins/members/sloan", headers=ADMIN).status_code == 204
    resp = client.get("/verify", headers=_bearer(sloan))
    assert resp.status_code == 200
    assert resp.json()["groups"] == ["admins"]

    assert client.delete("/admin/groups/admins/members/sloan", headers=ADMIN).status_code == 204
    assert client.get("/verify", headers=_bearer(sloan)).status_code == 403


def test_groups_are_created_and_listed_with_members(client):
    _create(client, "sloan")
    assert client.post("/admin/groups", json={"name": "kids"}, headers=ADMIN).status_code == 201
    assert client.post("/admin/groups", json={"name": "Kids"}, headers=ADMIN).status_code == 409
    assert client.put("/admin/groups/kids/members/sloan", headers=ADMIN).status_code == 204
    assert client.put("/admin/groups/kids/members/nobody", headers=ADMIN).status_code == 404
    assert client.put("/admin/groups/nogroup/members/sloan", headers=ADMIN).status_code == 404

    groups = {g["name"]: g["members"] for g in client.get("/admin/groups", headers=ADMIN).json()}
    assert groups == {"admins": ["daniel"], "kids": ["sloan"]}
    assert client.get("/admin/users/sloan", headers=ADMIN).json()["groups"] == ["kids"]


# -- T7: the hive is never left without an admin -------------------------------


def test_last_admin_cannot_be_disabled_or_removed_from_admins(client):
    assert client.patch("/admin/users/daniel", json={"disabled": True}, headers=ADMIN).status_code == 409
    assert client.delete("/admin/groups/admins/members/daniel", headers=ADMIN).status_code == 409
    daniel = client.get("/admin/users/daniel", headers=ADMIN).json()
    assert daniel["disabled"] is False
    assert daniel["groups"] == ["admins"]
    assert _login(client, SEED_USERNAME, SEED_PASSWORD).status_code == 200


def test_a_disabled_admin_does_not_count_toward_the_last_admin(client):
    _create(client, "sloan")
    client.put("/admin/groups/admins/members/sloan", headers=ADMIN)
    assert client.patch("/admin/users/sloan", json={"disabled": True}, headers=ADMIN).status_code == 200

    assert client.patch("/admin/users/daniel", json={"disabled": True}, headers=ADMIN).status_code == 409
    assert client.delete("/admin/groups/admins/members/daniel", headers=ADMIN).status_code == 409
    assert client.get("/admin/users/daniel", headers=ADMIN).json()["disabled"] is False


def test_with_a_second_enabled_admin_the_first_can_be_disabled(client):
    _create(client, "sloan")
    client.put("/admin/groups/admins/members/sloan", headers=ADMIN)
    assert client.patch("/admin/users/daniel", json={"disabled": True}, headers=ADMIN).status_code == 200
    # Now sloan is the last enabled admin.
    assert client.delete("/admin/groups/admins/members/sloan", headers=ADMIN).status_code == 409
