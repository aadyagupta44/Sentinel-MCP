"""PKCE helper tests."""

import base64
import hashlib

from sentinel.auth.pkce import code_challenge_s256, generate_code_verifier, generate_state


def test_verifier_is_url_safe_and_unpadded():
    v = generate_code_verifier()
    assert 43 <= len(v) <= 128
    assert "=" not in v
    assert "+" not in v
    assert "/" not in v


def test_verifiers_are_unique():
    assert len({generate_code_verifier() for _ in range(10)}) == 10


def test_challenge_matches_manual_s256():
    verifier = "test-verifier-fixed-value"
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    assert code_challenge_s256(verifier) == expected


def test_state_is_unique_and_unpadded():
    s = generate_state()
    assert "=" not in s
    assert len({generate_state() for _ in range(10)}) == 10
