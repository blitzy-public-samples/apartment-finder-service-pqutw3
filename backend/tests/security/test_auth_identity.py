"""SEC-02 regression tests for the subject claim and the identity column.

The suite checks minted claims directly and exercises guard behaviour
through ``/filters/``, which both persists and reads. The guard either
resolves the subject's account or returns a uniform 401.
"""
import calendar
import re
from datetime import datetime, timedelta

import pytest
from jose import JWTError, jwt

from backend.app.core.config import settings
from backend.app.core.security import (
    SESSION_COOKIE_NAME,
    _MAX_SUBJECT_ID,
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

# SEC-02: a primary key outside the range registration allocates
SEEDED_ID = 70

# SEC-02: the widest key models.py can map. PostgreSQL provisions User.id
# as SERIAL, whose sequence stops here; the value one past it is the
# boundary the guard has to refuse
MAPPED_KEY_CEILING = 2147483647
ABOVE_MAPPED_KEY_CEILING = 2147483648
# SEC-02: the name on a seeded filter row, read back through the guard
SEEDED_FILTER_NAME = "Owner filter"

# SEC-02: one valid create body, so the row under test arrives through the
# route and therefore through the guard
SEEDED_FILTER_BODY = {
    "name": SEEDED_FILTER_NAME,
    "criteria": [{"field": "rent", "operator": "lt", "value": "3000"}],
}


def bearer(token):
    """Return the Authorization header carrying one token."""
    return {"Authorization": "{0} {1}".format(BEARER_CHALLENGE, token)}


def create_filter(client, token):
    """Create one filter through the route and return its identifier.

    ``POST /filters/`` persists: it copies the validated allow-list onto
    mapped criteria children and supplies the server-owned timestamp. The
    row therefore arrives through the guard, which is what makes the
    ownership assertion below cover the write path as well as the read
    path.
    """
    response = client.post(
        PROTECTED_ROUTE, headers=bearer(token), json=SEEDED_FILTER_BODY
    )
    assert response.status_code == 200, response.text
    return response.json()["id"]


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
    """Each account reads its own filters and none belonging to another.

    The row is created through the route, so the guard resolves the
    subject twice: once to own the row on the way in, and once to select
    it on the way out. A row written straight to the session would assert
    the read path only.
    """
    owner = register_user()
    other = register_user()
    created_id = create_filter(client, owner["access_token"])

    owned = client.get(
        PROTECTED_ROUTE, headers=bearer(owner["access_token"])
    )
    assert owned.status_code == 200, owned.text
    # SEC-02: the guard resolved the subject to the owning key, so the
    # query filtered on it and returned only that account's row
    assert [row["id"] for row in owned.json()] == [created_id]
    assert [row["user_id"] for row in owned.json()] == [owner["id"]]

    foreign = client.get(
        PROTECTED_ROUTE, headers=bearer(other["access_token"])
    )
    assert foreign.status_code == 200, foreign.text
    # SEC-02: a different subject resolves to a different account
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

# SEC-02: subjects no account can carry - one past the key ceiling, and
# three past the canonical width
OUT_OF_RANGE_SUBJECTS = [
    pytest.param({"sub": str(2 ** 31)}, id="one-past-the-key-ceiling"),
    pytest.param({"sub": str(2 ** 63 - 1)}, id="at-the-64-bit-ceiling"),
    pytest.param({"sub": "9" * 19}, id="above-the-64-bit-ceiling"),
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
    """A subject wider than the id column is refused, not merely rejected.

    The guard screens the claim before any comparison is attempted, so
    the answer is the same uniform 401 challenge every other unusable
    subject receives. A guard that stopped screening would let the value
    reach the driver, which answers 500 through the sanitized boundary -
    a status this case has to distinguish from a refusal, because a
    server fault means the value was not screened at all.
    """
    response = client.get(
        PROTECTED_ROUTE, headers=bearer(create_access_token(payload))
    )
    # SEC-02: the uniform refusal, not any status at or above 400
    assert_refused(response)
    assert response.status_code != 500

    # SEC-08: the envelope carries exactly the frozen key set
    body = response.json()
    assert set(body) == {"detail", "error_id", "fields"}

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


def test_the_mapped_key_ceiling_still_resolves(client, db_session):
    """The widest key models.py maps sits inside the accepted range.

    A guard that refuses the ceiling value itself fails this case.
    """
    seed_account(db_session, MAPPED_KEY_CEILING)
    response = client.get(
        PROTECTED_ROUTE,
        headers=bearer(
            create_access_token({"sub": str(MAPPED_KEY_CEILING)})
        ),
    )
    assert response.status_code == 200
    assert response.json() == []


def test_a_subject_past_the_mapped_key_ceiling_is_refused(
    client, db_session
):
    """One key past the mapped ceiling is refused while its row exists.

    The harness column holds the value, so the refusal cannot come from
    the unresolved-account branch. A guard carrying a wider ceiling
    resolves the seeded row and answers 200. The refusal a client reads
    is the one the unresolved-account branch returns.
    """
    seed_account(db_session, ABOVE_MAPPED_KEY_CEILING)
    seeded = (
        db_session.query(User)
        .filter(User.id == ABOVE_MAPPED_KEY_CEILING)
        .first()
    )
    assert seeded is not None
    refused = client.get(
        PROTECTED_ROUTE,
        headers=bearer(
            create_access_token({"sub": str(ABOVE_MAPPED_KEY_CEILING)})
        ),
    )
    assert_refused(refused)
    assert refused.status_code != 200
    assert refused.status_code != 500
    unresolved = client.get(
        PROTECTED_ROUTE,
        headers=bearer(create_access_token({"sub": ABSENT_USER_ID})),
    )
    assert refusal_signature(refused) == refusal_signature(unresolved)


def test_the_subject_ceiling_matches_the_key_column_width(db_session):
    """The guard's ceiling is the width the id column actually declares.

    The column is INTEGER, which PostgreSQL emits as a signed 32-bit
    SERIAL. A ceiling wider than the column lets a value no key can hold
    past the guard and into the comparison, where the driver refuses it
    as a server fault rather than the guard refusing it as a 401.
    """
    # SEC-02: the signed 32-bit maximum the INTEGER key binds
    assert _MAX_SUBJECT_ID == 2 ** 31 - 1

    # the column the ceiling is derived from is still INTEGER
    key_column = User.__table__.columns["id"]
    assert key_column.type.__class__.__name__ == "Integer"

    # a key at the ceiling is storable, so the ceiling is not too wide
    seeded = seed_account(db_session, _MAX_SUBJECT_ID)
    assert seeded.id == _MAX_SUBJECT_ID


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
