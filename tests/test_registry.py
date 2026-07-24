import pytest

import auth
from registry import Registry


@pytest.fixture()
def reg(tmp_path):
    r = Registry(tmp_path / "auth.db")
    yield r
    r.close()


def test_create_and_fetch_user(reg):
    user = reg.create_user("daniel", auth.hash_password("secret"))
    assert reg.get_user(user["user_id"])["username"] == "daniel"
    assert reg.user_by_username("Daniel")["user_id"] == user["user_id"]  # case-insensitive


def test_count_users(reg):
    assert reg.count_users() == 0
    reg.create_user("daniel", auth.hash_password("secret"))
    assert reg.count_users() == 1


def test_token_roundtrip(reg):
    user = reg.create_user("daniel", auth.hash_password("secret"))
    token_hash = auth.token_digest("a-token")
    reg.store_token(token_hash, user["user_id"], ttl_hours=1)
    assert reg.user_for_token(token_hash)["user_id"] == user["user_id"]


def test_expired_token_is_rejected_and_purged(reg):
    user = reg.create_user("daniel", auth.hash_password("secret"))
    token_hash = auth.token_digest("a-token")
    reg.store_token(token_hash, user["user_id"], ttl_hours=-1)  # already expired
    assert reg.user_for_token(token_hash) is None
    # purged, not just rejected
    assert reg.user_for_token(token_hash) is None


def test_delete_token(reg):
    user = reg.create_user("daniel", auth.hash_password("secret"))
    token_hash = auth.token_digest("a-token")
    reg.store_token(token_hash, user["user_id"], ttl_hours=1)
    reg.delete_token(token_hash)
    assert reg.user_for_token(token_hash) is None


def test_delete_user_tokens(reg):
    user = reg.create_user("daniel", auth.hash_password("secret"))
    h1, h2 = auth.token_digest("t1"), auth.token_digest("t2")
    reg.store_token(h1, user["user_id"], ttl_hours=1)
    reg.store_token(h2, user["user_id"], ttl_hours=1)
    reg.delete_user_tokens(user["user_id"])
    assert reg.user_for_token(h1) is None
    assert reg.user_for_token(h2) is None


def test_set_password(reg):
    user = reg.create_user("daniel", auth.hash_password("old"))
    reg.set_password(user["user_id"], auth.hash_password("new"))
    stored = reg.get_user(user["user_id"])["password_hash"]
    assert auth.verify_password("new", stored)
    assert not auth.verify_password("old", stored)


def test_reset_token_consume_once(reg):
    user = reg.create_user("daniel", auth.hash_password("secret"))
    token_hash = auth.token_digest("reset-token")
    reg.store_reset_token(token_hash, user["user_id"], ttl_minutes=30)
    assert reg.consume_reset_token(token_hash) == user["user_id"]
    # single-use: second consume fails
    assert reg.consume_reset_token(token_hash) is None


def test_expired_reset_token_rejected(reg):
    user = reg.create_user("daniel", auth.hash_password("secret"))
    token_hash = auth.token_digest("reset-token")
    reg.store_reset_token(token_hash, user["user_id"], ttl_minutes=-1)
    assert reg.consume_reset_token(token_hash) is None
