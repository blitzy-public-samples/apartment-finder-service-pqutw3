"""Access-token verification at the HTTP boundary.

Every case in this module presents a crafted access token on a
protected route and asserts that the request is refused. The refusal
asserted is the one
:func:`backend.app.core.security.get_current_user` raises for any token
it will not accept: status ``401``, the body
``{"detail": "Could not validate credentials"}`` and the header
``WWW-Authenticate: Bearer``.

Three families of case run against that contract.

* Algorithm -- a token declaring ``none`` in any letter case, a token
  correctly signed with an algorithm absent from the accepted list, a
  token correctly signed with an asymmetric algorithm, and a token
  declaring an asymmetric algorithm over an empty signature are each
  refused.
* Subject -- a token whose subject is a stored address, and a token
  whose subject is not an integer, are each refused.
* Refusal uniformity -- the response for a deleted account, and the
  response for a subject naming no stored row, are each
  indistinguishable from the response an invalid token receives, in
  status code, in body bytes, in decoded body and in challenge header.

The remaining cases assert that a foreign signing key, an elapsed
expiry, a not-before time still in the future, a foreign audience, a
foreign issuer and each individually absent required claim are refused.

:func:`test_the_reference_token_is_accepted` presents the token every
forgery here is derived from, which differs from each forgery in that
forgery's defect and in nothing else.

Every token is minted by the ``forged_token_factory`` fixture published
by ``backend/tests/conftest.py``, and every forgery names the seeded
``registered_user`` row.
"""

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

#: Route every token in this module is presented on. Both of its
#: methods resolve their principal through
#: :func:`backend.app.core.authorization.require_role`.
PROTECTED_PATH = "/filters/"

#: Status code carried by every refusal asserted here.
REFUSED_STATUS = 401

#: Decoded body carried by every refusal asserted here.
REFUSED_BODY = {"detail": "Could not validate credentials"}

#: Response header naming the scheme a refused caller may retry with.
CHALLENGE_HEADER = "WWW-Authenticate"

#: Value :data:`CHALLENGE_HEADER` carries on every refusal.
CHALLENGE_VALUE = "Bearer"

#: Status code the reference token receives.
ACCEPTED_STATUS = 200

#: Letter cases of the unsigned algorithm name presented in a header.
NONE_ALGORITHM_SPELLINGS = ("none", "None", "NONE", "NoNe")

#: Asymmetric algorithm name the confusion cases declare.
ASYMMETRIC_ALGORITHM = "RS256"

#: The claims a token must carry.
#: :func:`test_the_claim_drop_cases_cover_every_required_claim` holds
#: this tuple equal to
#: :data:`backend.app.core.security.REQUIRED_CLAIMS`.
REQUIRED_CLAIM_NAMES = ("exp", "iat", "nbf", "sub", "aud", "iss", "jti")

#: Subjects that ``int`` does not read as a row identifier.
NON_INTEGER_SUBJECTS = ("", "   ", "not-an-integer", "1.0")

#: Distance above the seeded row's identifier used to name no row.
UNUSED_IDENTIFIER_OFFSET = 1000

# Parameters of the throwaway RSA key the asymmetric forgery is signed
# with.
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
    """Return the algorithm name the token's own header declares."""
    return jwt.get_unverified_header(token)["alg"]


def carried_claims(token):
    """Return the claims the token carries, verifying nothing."""
    return jwt.decode(token, options={"verify_signature": False})


def assert_refused(response):
    """Assert the response is the refusal a rejected token receives."""
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
    """Asserts an unlisted algorithm is refused though signed correctly.

    The token is signed with the configured key, and its signature is
    correct for the algorithm its header declares.
    """
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
    """Asserts a correctly signed asymmetric token is refused.

    The token is signed with a throwaway RSA key and its header
    declares that key's algorithm.
    """
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
    """Asserts a token whose only defect is its key is refused.

    The foreign key is not the configured key and is no shorter than
    the configured floor, and the token carries every required claim
    and is unexpired.
    """
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
    """Asserts a subject naming a stored address is refused.

    The address is the one the stored row holds, and that row's own
    identifier is an integer.
    """
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
    """Asserts a deleted account draws the invalid-token refusal.

    The token is accepted while the row exists, the row is then
    removed, and the refusal that follows is compared with the refusal
    an invalid token draws in the same test.
    """
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
    """Asserts a subject naming no row draws the same refusal.

    The identifier is confirmed absent from the database before the
    token naming it is presented.
    """
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
