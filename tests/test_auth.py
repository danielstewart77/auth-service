import auth


def test_hash_and_verify_roundtrip():
    encoded = auth.hash_password("correct horse")
    assert auth.verify_password("correct horse", encoded)


def test_verify_rejects_wrong_password():
    encoded = auth.hash_password("correct horse")
    assert not auth.verify_password("wrong password", encoded)


def test_hash_rejects_empty_password():
    try:
        auth.hash_password("")
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_verify_rejects_garbage_encoding():
    assert not auth.verify_password("anything", "not-a-real-hash")


def test_token_digest_is_deterministic_and_not_the_token():
    token = auth.new_token()
    digest = auth.token_digest(token)
    assert digest == auth.token_digest(token)
    assert digest != token


def test_bearer_parses_authorization_header():
    assert auth.bearer("Bearer abc123") == "abc123"
    assert auth.bearer("bearer abc123") == "abc123"


def test_bearer_rejects_non_bearer_scheme():
    assert auth.bearer("Basic abc123") is None


def test_bearer_handles_missing_header():
    assert auth.bearer(None) is None
