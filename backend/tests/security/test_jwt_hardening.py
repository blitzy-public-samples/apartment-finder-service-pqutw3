import time
from functools import lru_cache

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from backend.app.core.config import MIN_SIGNING_KEY_BYTES, settings
from backend.app.core.security import JWT_ALGORITHMS, REQUIRED_CLAIMS
from backend.app.db.models import User
from backend.tests.support import (
    FOREIGN_AUDIENCE,
    FOREIGN_ISSUER,
    FOREIGN_SIGNING_KEY,
    bearer_header,
)

PROTECTED_PATH = "/filters/"

REFUSED_STATUS = 401

REFUSED_BODY = {"detail": "Could not validate credentials"}

CHALLENGE_HEADER = "WWW-Authenticate"

CHALLENGE_VALUE = "Bearer"

ACCEPTED_STATUS = 200

NONE_ALGORITHM_SPELLINGS = ("none", "None", "NONE", "NoNe")

ASYMMETRIC_ALGORITHM = "RS256"

REQUIRED_CLAIM_NAMES = ("exp", "iat", "nbf", "sub", "aud", "iss", "jti")

NON_INTEGER_SUBJECTS = ("", "   ", "not-an-integer", "1.0")

UNUSED_IDENTIFIER_OFFSET = 1000

_RSA_PUBLIC_EXPONENT = 65537
_RSA_KEY_SIZE = 2048


@lru_cache(maxsize=1)
def attacker_signing_key():
    """Return a PEM RSA private key no part of the service holds.

    The key is generated once per session and returned as a PKCS#8 PEM
    string.
    """
    generated = rsa.generate_private_key(
        public_exponent=_RSA_PUBLIC_EXPONENT,
        key_size=_RSA_KEY_SIZE,
    )
    return generated.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def present(client, token):
    """Return the response :data:`PROTECTED_PATH` gives for ``token``.

    The token travels in the ``Authorization`` header as a bearer
    credential.
    """
    return client.get(PROTECTED_PATH, headers=bearer_header(token))


def declared_algorithm(token):
    return jwt.get_unverified_header(token)["alg"]


def carried_claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def assert_refused(response):
    assert response.status_code == REFUSED_STATUS
    assert response.json() == REFUSED_BODY
    assert response.headers[CHALLENGE_HEADER] == CHALLENGE_VALUE


def assert_indistinguishable(first, second):
    """Assert two refusals present a caller with the same response.

    The status code, the raw body bytes, the decoded body and the
    challenge header are all compared.
    """
    assert first.status_code == second.status_code
    assert first.content == second.content
    assert first.json() == second.json()
    assert (
        first.headers[CHALLENGE_HEADER]
        == second.headers[CHALLENGE_HEADER]
    )


def test_the_reference_token_is_accepted(
    client, forged_token_factory, registered_user
):
    response = present(
        client, forged_token_factory.valid(sub=str(registered_user.id))
    )
    assert response.status_code == ACCEPTED_STATUS
    assert response.json() == []
    assert CHALLENGE_HEADER not in response.headers


@pytest.mark.parametrize("spelling", NONE_ALGORITHM_SPELLINGS)
def test_finding_c2_a_token_declaring_none_is_rejected(
    client, forged_token_factory, registered_user, spelling
):
    token = forged_token_factory.unsigned(
        spelling, sub=str(registered_user.id)
    )
    assert declared_algorithm(token) == spelling
    assert token.endswith(".")
    assert_refused(present(client, token))


def test_finding_c2_a_token_declaring_an_unlisted_algorithm_is_rejected(
    client, forged_token_factory, registered_user
):
    token = forged_token_factory.unlisted_algorithm(
        sub=str(registered_user.id)
    )
    algorithm = declared_algorithm(token)
    assert algorithm not in JWT_ALGORITHMS
    assert algorithm not in settings.JWT_ALGORITHMS
    assert_refused(present(client, token))


def test_finding_c2_an_asymmetric_algorithm_is_rejected(
    client, forged_token_factory, registered_user
):
    token = forged_token_factory.forge(
        key=attacker_signing_key(),
        algorithm=ASYMMETRIC_ALGORITHM,
        sub=str(registered_user.id),
    )
    assert declared_algorithm(token) == ASYMMETRIC_ALGORITHM
    assert ASYMMETRIC_ALGORITHM not in JWT_ALGORITHMS
    assert ASYMMETRIC_ALGORITHM not in settings.JWT_ALGORITHMS
    assert_refused(present(client, token))


def test_finding_c2_a_stripped_asymmetric_signature_is_rejected(
    client, forged_token_factory, registered_user
):
    token = forged_token_factory.unsigned(
        ASYMMETRIC_ALGORITHM, sub=str(registered_user.id)
    )
    assert declared_algorithm(token) == ASYMMETRIC_ALGORITHM
    assert token.endswith(".")
    assert_refused(present(client, token))


def test_a_token_signed_with_a_foreign_key_is_rejected(
    client, forged_token_factory, registered_user
):
    assert FOREIGN_SIGNING_KEY != settings.SECRET_KEY
    assert (
        len(FOREIGN_SIGNING_KEY.encode("utf-8"))
        >= MIN_SIGNING_KEY_BYTES
    )
    token = forged_token_factory.wrong_key(sub=str(registered_user.id))
    assert declared_algorithm(token) in JWT_ALGORITHMS
    claims = carried_claims(token)
    assert set(REQUIRED_CLAIM_NAMES) <= set(claims)
    assert claims["exp"] > time.time()
    assert_refused(present(client, token))


def test_an_expired_token_is_rejected(
    client, forged_token_factory, registered_user
):
    token = forged_token_factory.expired(sub=str(registered_user.id))
    assert carried_claims(token)["exp"] < time.time()
    assert_refused(present(client, token))


def test_a_token_whose_validity_has_not_begun_is_rejected(
    client, forged_token_factory, registered_user
):
    token = forged_token_factory.future_not_before(
        sub=str(registered_user.id)
    )
    claims = carried_claims(token)
    assert claims["nbf"] > time.time()
    assert claims["exp"] > claims["nbf"]
    assert_refused(present(client, token))


def test_a_token_carrying_a_foreign_audience_is_rejected(
    client, forged_token_factory, registered_user
):
    assert FOREIGN_AUDIENCE != settings.JWT_AUDIENCE
    token = forged_token_factory.wrong_audience(
        sub=str(registered_user.id)
    )
    assert carried_claims(token)["aud"] == FOREIGN_AUDIENCE
    assert_refused(present(client, token))


def test_a_token_carrying_a_foreign_issuer_is_rejected(
    client, forged_token_factory, registered_user
):
    assert FOREIGN_ISSUER != settings.JWT_ISSUER
    token = forged_token_factory.wrong_issuer(
        sub=str(registered_user.id)
    )
    assert carried_claims(token)["iss"] == FOREIGN_ISSUER
    assert_refused(present(client, token))


@pytest.mark.parametrize("claim", REQUIRED_CLAIM_NAMES)
def test_a_token_missing_a_required_claim_is_rejected(
    client, forged_token_factory, registered_user, claim
):
    token = forged_token_factory.without_claim(
        claim, sub=str(registered_user.id)
    )
    assert claim not in carried_claims(token)
    assert_refused(present(client, token))


def test_the_claim_drop_cases_cover_every_required_claim():
    assert REQUIRED_CLAIM_NAMES == tuple(REQUIRED_CLAIMS)


def test_finding_h7_a_token_whose_subject_is_an_address_is_rejected(
    client, forged_token_factory, registered_user
):
    token = forged_token_factory.legacy_email_subject(
        email=registered_user.email
    )
    assert carried_claims(token)["sub"] == registered_user.email
    assert isinstance(registered_user.id, int)
    assert_refused(present(client, token))


@pytest.mark.parametrize("subject", NON_INTEGER_SUBJECTS)
def test_finding_h7_a_subject_that_is_not_an_integer_is_rejected(
    client, forged_token_factory, registered_user, subject
):
    assert str(registered_user.id) != subject
    token = forged_token_factory.valid(sub=subject)
    assert carried_claims(token)["sub"] == subject
    assert_refused(present(client, token))


def test_finding_m1_a_deleted_account_is_refused_like_a_bad_token(
    client, db, forged_token_factory, registered_user
):
    subject = str(registered_user.id)
    token = forged_token_factory.valid(sub=subject)
    assert present(client, token).status_code == ACCEPTED_STATUS
    db.delete(registered_user)
    db.commit()
    deleted = present(client, token)
    invalid = present(
        client, forged_token_factory.wrong_key(sub=subject)
    )
    assert_refused(deleted)
    assert_refused(invalid)
    assert_indistinguishable(deleted, invalid)


def test_finding_m1_an_unknown_subject_is_refused_like_a_bad_token(
    client, db, forged_token_factory, registered_user
):
    unknown = registered_user.id + UNUSED_IDENTIFIER_OFFSET
    assert db.query(User).filter(User.id == unknown).first() is None
    absent = present(
        client, forged_token_factory.valid(sub=str(unknown))
    )
    invalid = present(
        client,
        forged_token_factory.wrong_key(sub=str(registered_user.id)),
    )
    assert_refused(absent)
    assert_refused(invalid)
    assert_indistinguishable(absent, invalid)
