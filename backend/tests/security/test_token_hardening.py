"""Regression tests for the access-token minting and verification rules.

Each case corresponds to a token a caller could previously obtain, or a
verification decision the process could previously be talked out of, and
asserts that it is no longer possible.
"""

from datetime import timedelta

import jwt
import pytest

from backend.app.core import security
from backend.app.core.config import settings


def decode(token, **overrides):
    """Decodes a token the way the application does, plus overrides."""
    options = {"require": list(security.REQUIRED_CLAIMS)}
    arguments = {
        "key": settings.SECRET_KEY,
        "algorithms": list(security.JWT_ALGORITHMS),
        "audience": settings.JWT_AUDIENCE,
        "issuer": settings.JWT_ISSUER,
        "options": options,
    }
    arguments.update(overrides)
    return jwt.decode(token, **arguments)


class TestAlgorithmsAreFixedAtImport:
    """The accepted algorithms cannot be changed after startup."""

    def test_accepted_algorithms_are_an_immutable_tuple(self):
        assert isinstance(security.JWT_ALGORITHMS, tuple)
        with pytest.raises((TypeError, AttributeError)):
            security.JWT_ALGORITHMS[0] = "HS512"

    def test_signing_algorithm_is_the_first_accepted_algorithm(self):
        assert (
            security.SIGNING_ALGORITHM == security.JWT_ALGORITHMS[0]
        )

    def test_every_accepted_algorithm_is_on_the_configured_allowlist(
        self,
    ):
        for algorithm in security.JWT_ALGORITHMS:
            assert algorithm in settings.JWT_ALGORITHMS

    def test_mutating_the_setting_list_does_not_change_signing(self):
        """A setting list mutated in place must not reach the token.

        ``settings.JWT_ALGORITHMS`` is a list, so it is mutable at run
        time. Signing reads the frozen tuple instead.
        """
        original = list(settings.JWT_ALGORITHMS)
        try:
            settings.JWT_ALGORITHMS.append("HS512")
            token = security.create_access_token({"sub": "1"})
            assert (
                jwt.get_unverified_header(token)["alg"]
                == security.SIGNING_ALGORITHM
            )
            assert "HS512" not in security.JWT_ALGORITHMS
        finally:
            settings.JWT_ALGORITHMS[:] = original

    def test_mutating_the_setting_list_does_not_change_verification(
        self, monkeypatch
    ):
        """Verification is handed the frozen tuple, not the setting.

        The algorithms argument reaching the decoder is recorded, so the
        assertion covers what the verifier is actually told to accept
        rather than what it happens to reject.
        """
        recorded = {}

        def record(token, key, **kwargs):
            recorded.update(kwargs)
            raise jwt.InvalidTokenError("recorded")

        monkeypatch.setattr(security.jwt, "decode", record)
        original = list(settings.JWT_ALGORITHMS)
        try:
            settings.JWT_ALGORITHMS.append("HS512")
            with pytest.raises(Exception):
                security.get_current_user(token="any", db=None)
        finally:
            settings.JWT_ALGORITHMS[:] = original
        assert recorded["algorithms"] == list(security.JWT_ALGORITHMS)
        assert "HS512" not in recorded["algorithms"]
        assert recorded["audience"] == settings.JWT_AUDIENCE
        assert recorded["issuer"] == settings.JWT_ISSUER
        assert recorded["options"]["require"] == list(
            security.REQUIRED_CLAIMS
        )

    def test_an_unsigned_token_is_refused(self):
        forged = jwt.encode(
            {"sub": "1"}, key=None, algorithm=None
        )
        with pytest.raises(jwt.PyJWTError):
            decode(forged)


class TestTokenLifetimeIsBounded:
    """No caller can mint a token outliving the configured maximum."""

    def test_default_lifetime_is_the_configured_maximum(self):
        token = security.create_access_token({"sub": "1"})
        payload = decode(token)
        lifetime = payload["exp"] - payload["iat"]
        assert lifetime == int(
            security.MAX_TOKEN_LIFETIME.total_seconds()
        )

    def test_maximum_matches_the_configured_minutes(self):
        assert security.MAX_TOKEN_LIFETIME == timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    def test_a_shorter_lifetime_is_honoured(self):
        requested = timedelta(minutes=1)
        assert requested <= security.MAX_TOKEN_LIFETIME
        token = security.create_access_token(
            {"sub": "1"}, expires_delta=requested
        )
        payload = decode(token)
        assert payload["exp"] - payload["iat"] == int(
            requested.total_seconds()
        )

    def test_the_maximum_itself_is_honoured(self):
        token = security.create_access_token(
            {"sub": "1"}, expires_delta=security.MAX_TOKEN_LIFETIME
        )
        payload = decode(token)
        assert payload["exp"] - payload["iat"] == int(
            security.MAX_TOKEN_LIFETIME.total_seconds()
        )

    @pytest.mark.parametrize(
        "delta",
        [
            timedelta(days=365),
            timedelta(days=1),
            timedelta(minutes=1) + timedelta(seconds=1),
        ],
    )
    def test_a_longer_lifetime_is_refused(self, delta):
        oversized = max(
            delta, security.MAX_TOKEN_LIFETIME + timedelta(seconds=1)
        )
        with pytest.raises(ValueError):
            security.create_access_token(
                {"sub": "1"}, expires_delta=oversized
            )

    @pytest.mark.parametrize(
        "delta",
        [
            timedelta(0),
            timedelta(seconds=-1),
            timedelta(days=-30),
        ],
    )
    def test_a_non_positive_lifetime_is_refused(self, delta):
        with pytest.raises(ValueError):
            security.create_access_token(
                {"sub": "1"}, expires_delta=delta
            )


class TestMintedClaims:
    """Every required claim is minted and none can be displaced."""

    def test_all_required_claims_are_present(self):
        payload = decode(security.create_access_token({"sub": "7"}))
        for claim in security.REQUIRED_CLAIMS:
            assert claim in payload

    def test_supplied_data_cannot_replace_a_minted_claim(self):
        token = security.create_access_token(
            {
                "sub": "7",
                "iss": "attacker",
                "aud": "attacker",
                "jti": "attacker",
            }
        )
        payload = decode(token)
        assert payload["iss"] == settings.JWT_ISSUER
        assert payload["aud"] == settings.JWT_AUDIENCE
        assert payload["jti"] != "attacker"

    def test_each_token_carries_a_distinct_identifier(self):
        first = decode(security.create_access_token({"sub": "7"}))
        second = decode(security.create_access_token({"sub": "7"}))
        assert first["jti"] != second["jti"]
