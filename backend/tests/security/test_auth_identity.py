"""SEC-02 regression tests for the subject claim and the identity column.

The suite checks minted claims directly and exercises guard behaviour
through ``GET /filters/``. The guard either resolves the subject's
account or returns a uniform 401.
"""
import calendar
import re
from datetime import datetime, timedelta

import pytest
from jose import JWTError, jwt

from backend.app.core.config import settings
from backend.app.core.security import (
    SESSION_COOKIE_NAME,
    create_access_token,
)
from backend.app.db.models import User

# SEC-02: the authenticated route the guard defends. No /api segment
# exists and the trailing slash belongs to the declared path.
PROTECTED_ROUTE = "/filters/"

# SEC-02: the refusal every credential failure returns.
# handle_http_exception in backend/app/main.py replaces the raised detail
# with the status phrase.
REFUSED_STATUS = 401
REFUSED_DETAIL = "Unauthorized"
BEARER_CHALLENGE = "Bearer"

# SEC-08: the per-response correlation identifier in the error envelope
CORRELATION_ID = re.compile(r"[0-9a-f]{32}")

ABSENT_USER_ID = "999999"

ABSENT_EMAIL = "no-such-account@example.com"

MALFORMED_TOKEN = "not.a.token"

# SEC-02: a value for the non-null hash column on a seeded row
SEEDED_HASH = "x" * 60

# SEC-02: a primary key registration would not hand out on its own
SEEDED_ID = 70


def bearer(token):
    """Return the Authorization header carrying one token."""
    return {"Authorization": "{0} {1}".format(BEARER_CHALLENGE, token)}


def claims_of(token):
    """Return the claims the signed token carries."""
    return jwt.decode(
        token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )


def refusal_signature(response):
    """Return the parts of a refusal that every failure path shares.

    The correlation identifier is excluded.
    """
    body = response.json()
    return (
        response.status_code,
        body["detail"],
        tuple(body["fields"]),
        response.headers.get("WWW-Authenticate"),
    )


def assert_refused(response):
    """Assert one response is the uniform refusal with a correlation id."""
    assert response.status_code == REFUSED_STATUS
    body = response.json()
    assert body["detail"] == REFUSED_DETAIL
    assert body["fields"] == []
    assert response.headers.get("WWW-Authenticate") == BEARER_CHALLENGE
    assert CORRELATION_ID.fullmatch(body["error_id"])


def seed_account(db_session, user_id):
    """Persist one account carrying the exact integer primary key.

    Registration assigns the key, so a test that needs a chosen key
    inserts the row itself. The hash column holds a placeholder: no
    assertion here reads it and no login path runs against it.
    """
    row = User(
        id=user_id,
        email="seeded-{0}@example.com".format(user_id),
        hashed_password=SEEDED_HASH,
        created_at=datetime.utcnow(),
    )
    db_session.add(row)
    db_session.commit()
    return row


# SEC-02: mints sub as user id; closes the sub/User.id identity mismatch
def test_minted_subject_is_the_decimal_user_id(register_user):
    """The subject claim carries the user id, spelled as a string."""
    account = register_user()
    subject = claims_of(account["access_token"])["sub"]
    assert isinstance(subject, str)
    assert subject == str(account["id"])
    assert int(subject) == account["id"]


def test_subject_coerces_to_the_persisted_integer_key(
    register_user, db_session
):
    """The coerced subject equals the integer primary key on the row."""
    account = register_user()
    row = (
        db_session.query(User)
        .filter(User.email == account["email"])
        .first()
    )
    assert row is not None
    assert isinstance(row.id, int)
    assert not isinstance(row.id, bool)
    assert int(claims_of(account["access_token"])["sub"]) == row.id


def test_bearer_header_reaches_the_protected_route(client, register_user):
    """A registered account reaches the route over the bearer header."""
    account = register_user()
    response = client.get(
        PROTECTED_ROUTE, headers=bearer(account["access_token"])
    )
    assert response.status_code == 200
    assert response.json() == []


def test_session_cookie_reaches_the_protected_route(client, register_user):
    """A registered account reaches the route over the session cookie."""
    account = register_user()
    client.cookies.set(SESSION_COOKIE_NAME, account["access_token"])
    response = client.get(PROTECTED_ROUTE)
    assert response.status_code == 200
    assert response.json() == []


def test_guard_resolves_the_owning_account(client, register_user):
    """Each account reads its own filters and none belonging to another."""
    owner = register_user()
    other = register_user()
    created = client.post(
        PROTECTED_ROUTE,
        json={
            "name": "Owner filter",
            "criteria": [
                {"field": "rent", "operator": "lt", "value": "3000"},
            ],
        },
        headers=bearer(owner["access_token"]),
    )
    assert created.status_code == 200
    assert created.json()["user_id"] == str(owner["id"])
    owned = client.get(
        PROTECTED_ROUTE, headers=bearer(owner["access_token"])
    )
    assert owned.status_code == 200
    assert [row["user_id"] for row in owned.json()] == [str(owner["id"])]
    foreign = client.get(
        PROTECTED_ROUTE, headers=bearer(other["access_token"])
    )
    assert foreign.status_code == 200
    assert foreign.json() == []


def test_email_subject_is_refused_for_a_registered_account(
    client, register_user
):
    """A token naming a registered account by email is refused."""
    account = register_user()
    response = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": account["email"]})),
    )
    assert_refused(response)
    assert response.status_code != 500


def test_email_subject_is_refused_for_an_absent_account(client):
    """A token naming an unregistered email is refused."""
    response = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": ABSENT_EMAIL})),
    )
    assert_refused(response)
    assert response.status_code != 500


def test_email_subject_refusals_are_indistinguishable(client, register_user):
    """A registered and an unregistered email produce one refusal."""
    account = register_user()
    known = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": account["email"]})),
    )
    unknown = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": ABSENT_EMAIL})),
    )
    assert refusal_signature(known) == refusal_signature(unknown)


# SEC-02: unresolvable subject answers 401, not 404
def test_unresolvable_subject_is_refused(client):
    """A subject matching no account is refused, not reported missing."""
    response = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": ABSENT_USER_ID})),
    )
    assert_refused(response)
    assert response.status_code != 404


def test_unresolved_and_malformed_refusals_match(client):
    """An unresolved subject and an unreadable token draw one refusal."""
    unresolved = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": ABSENT_USER_ID})),
    )
    malformed = client.get(PROTECTED_ROUTE, headers=bearer(MALFORMED_TOKEN))
    assert refusal_signature(unresolved) == refusal_signature(malformed)


def test_a_refusal_names_no_account_state(client):
    """A refusal body reveals no account state and no raised detail."""
    response = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": ABSENT_USER_ID})),
    )
    body = response.text.lower()
    for leaked in (
        "not found",
        "could not validate",
        "user",
        "traceback",
        "sqlalchemy",
        "select ",
    ):
        assert leaked not in body


def test_minted_token_stamps_the_issuance_time(register_user):
    """Every minted token carries an issued-at claim beside the expiry."""
    before = calendar.timegm(datetime.utcnow().utctimetuple())
    account = register_user()
    after = calendar.timegm(datetime.utcnow().utctimetuple())
    claims = claims_of(account["access_token"])
    assert "iat" in claims
    assert "exp" in claims
    assert isinstance(claims["iat"], int)
    assert not isinstance(claims["iat"], bool)
    assert before <= claims["iat"] <= after
    assert claims["iat"] <= claims["exp"]
    window = settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    assert claims["exp"] - claims["iat"] <= window


# SEC-02: payloads carrying nothing the guard can coerce to a key
REFUSED_SUBJECTS = [
    pytest.param({}, id="absent-subject"),
    pytest.param({"sub": ""}, id="empty-subject"),
    pytest.param({"sub": "1e3"}, id="exponent-subject"),
    pytest.param({"sub": "0x7"}, id="hexadecimal-subject"),
]

# SEC-02: subjects no account can carry - the first clears the canonical
# width but exceeds the key ceiling, the second exceeds the width itself
OUT_OF_RANGE_SUBJECTS = [
    pytest.param({"sub": "9" * 19}, id="above-the-key-ceiling"),
    pytest.param({"sub": "9" * 20}, id="overlong-subject"),
]


@pytest.mark.parametrize("payload", REFUSED_SUBJECTS)
def test_uncoercible_subject_is_refused(client, payload):
    """A subject the guard cannot read as a user id is refused.

    Coercing any of these payloads raises, so a guard that stops
    screening the claim answers 500 and the case fails.
    """
    response = client.get(
        PROTECTED_ROUTE, headers=bearer(create_access_token(payload))
    )
    assert_refused(response)
    assert response.status_code != 500


@pytest.mark.parametrize("payload", OUT_OF_RANGE_SUBJECTS)
def test_out_of_range_subject_reaches_no_account(client, payload):
    """A subject wider than the id column resolves no account and leaks
    nothing.

    The guard refuses both spellings before any comparison is attempted,
    and the uniform envelope carries no driver text.
    """
    response = client.get(
        PROTECTED_ROUTE, headers=bearer(create_access_token(payload))
    )
    # SEC-02: no account is ever returned for an out-of-range subject
    assert response.status_code >= 400
    body = response.json()
    assert set(body) == {"detail", "error_id", "fields"}
    assert body["fields"] == []
    assert CORRELATION_ID.fullmatch(body["error_id"])
    # SEC-08: no traceback, driver text or statement reaches the caller
    lowered = response.text.lower()
    for leaked in ("traceback", "overflow", "sqlalchemy", ".py", "select "):
        assert leaked not in lowered, leaked
    assert payload["sub"] not in response.text


# SEC-02: subject values that are not strings at all
NON_STRING_SUBJECTS = [
    pytest.param(12345, id="integer-subject"),
    pytest.param(["7"], id="list-subject"),
    pytest.param({"id": "7"}, id="mapping-subject"),
]


@pytest.mark.parametrize("subject", NON_STRING_SUBJECTS)
def test_non_string_subject_never_reaches_the_lookup(client, subject):
    """A subject that is not a string is refused at the token boundary.

    Decoding rejects the claim before the guard reads it, and the guard
    screens the same case again. Both layers are asserted here: the
    decode raises, and the request draws the uniform refusal.
    """
    token = create_access_token({"sub": subject})
    with pytest.raises(JWTError):
        claims_of(token)
    response = client.get(PROTECTED_ROUTE, headers=bearer(token))
    assert_refused(response)
    assert response.status_code != 500


# SEC-02: subject spellings int() reads, each paired with the primary key
# it resolves to
COERCIBLE_SUBJECTS = [
    pytest.param(12345, 12345, id="integer-subject"),
    pytest.param("0", 0, id="zero-subject"),
    pytest.param("007", 7, id="zero-padded-subject"),
    pytest.param(" 7", 7, id="leading-space-subject"),
    pytest.param("7 ", 7, id="trailing-space-subject"),
    pytest.param("\n7", 7, id="newline-subject"),
    pytest.param("+7", 7, id="signed-subject"),
    pytest.param("-7", -7, id="negative-subject"),
    pytest.param("7_0", 70, id="underscored-subject"),
    pytest.param("\uff17", 7, id="fullwidth-digit-subject"),
]


@pytest.mark.parametrize("subject,resolvable_id", COERCIBLE_SUBJECTS)
def test_coercible_subject_is_refused_before_the_lookup(
    client, db_session, subject, resolvable_id
):
    """A coercible subject is refused while its account exists.

    The row the coercion would reach is seeded first, so the refusal
    cannot come from the unresolved-account branch. A guard that stops
    screening the claim resolves the seeded row and answers 200.
    """
    seed_account(db_session, resolvable_id)
    seeded = db_session.query(User).filter(User.id == resolvable_id).first()
    assert seeded is not None
    response = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": subject})),
    )
    assert_refused(response)
    assert response.status_code != 200
    assert response.status_code != 500


def test_a_seeded_account_answers_its_canonical_subject(client, db_session):
    """The canonical spelling of a seeded key reaches the route.

    This is the control for the refusals above: the same seeding path
    produces an account the guard resolves.
    """
    seed_account(db_session, SEEDED_ID)
    response = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": str(SEEDED_ID)})),
    )
    assert response.status_code == 200
    assert response.json() == []


def test_integer_subject_is_refused_for_a_registered_account(
    client, register_user
):
    """One registered key is refused as an integer, accepted as a string.

    Both tokens name the same live account, so the refusal turns on the
    type of the claim and on nothing else.
    """
    account = register_user()
    refused = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": account["id"]})),
    )
    assert_refused(refused)
    assert refused.status_code != 500
    accepted = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": str(account["id"])})),
    )
    assert accepted.status_code == 200


def test_expired_token_is_refused(client, register_user):
    """A token past its expiry is refused, even naming a real account."""
    account = register_user()
    expired = create_access_token(
        {"sub": str(account["id"])}, timedelta(minutes=-5)
    )
    response = client.get(PROTECTED_ROUTE, headers=bearer(expired))
    assert_refused(response)


def test_a_request_without_a_credential_is_refused(client):
    """A request carrying no credential at all is refused."""
    assert_refused(client.get(PROTECTED_ROUTE))


def test_a_refused_token_in_the_session_cookie_is_refused(client):
    """The cookie transport reaches the same guard as the header."""
    client.cookies.set(
        SESSION_COOKIE_NAME, create_access_token({"sub": ABSENT_USER_ID})
    )
    assert_refused(client.get(PROTECTED_ROUTE))


def test_every_credential_failure_path_answers_alike(client, register_user):
    """The four credential failure paths return the same refusal.

    Each response carries its own correlation identifier, and the parts a
    client can read are identical across all four.
    """
    account = register_user()
    refusals = {
        "absent subject": client.get(
            PROTECTED_ROUTE, headers=bearer(create_access_token({}))
        ),
        "unreadable token": client.get(
            PROTECTED_ROUTE, headers=bearer(MALFORMED_TOKEN)
        ),
        "uncoercible subject": client.get(
            PROTECTED_ROUTE,
            headers=bearer(create_access_token({"sub": account["email"]})),
        ),
        "unresolved subject": client.get(
            PROTECTED_ROUTE,
            headers=bearer(create_access_token({"sub": ABSENT_USER_ID})),
        ),
    }
    signatures = {
        name: refusal_signature(response)
        for name, response in refusals.items()
    }
    assert len(set(signatures.values())) == 1, signatures
    for response in refusals.values():
        assert_refused(response)
    correlation_ids = {
        response.json()["error_id"] for response in refusals.values()
    }
    assert len(correlation_ids) == len(refusals)
