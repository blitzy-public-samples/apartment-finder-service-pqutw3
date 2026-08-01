"""SEC-04 regression tests for the server-side password policy.

Every case reaches the policy through ``POST /auth/register``, whose
body FastAPI validates against ``UserCreate`` before the route hashes
anything. The matching client-side rule in
``frontend/src/utils/validators.ts`` runs in no browser today, so the
server holds the only copy that a caller cannot bypass.

The cases run at two layers. The HTTP layer pins the status code, the
field name and the absence of any database row. The schema layer pins
the character set and reports a direct failure when a rule moves.

The stored value is checked too. Every ceiling below is a bcrypt input
limit, so the scheme that produced the hash is part of the policy rather
than an implementation detail behind it.
"""
import pytest
from pydantic import ValidationError
from sqlalchemy import text

from backend.app.core.security import verify_password
from backend.app.schema.user import UserCreate

# There is no /api prefix: router.py applies /auth and main.py includes
# the router without one.
REGISTER_PATH = "/auth/register"

# Address for the schema-level cases, which send no request.
SCHEMA_EMAIL = "policy-probe@example.com"

MIN_LENGTH = 12
MAX_BYTES = 72

# SEC-04: 30-character special set mirrors validators.ts:23
SPECIALS = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?"
SPECIAL_COUNT = 30

# Punctuation the client rule leaves out of its character class.
EXCLUDED_PUNCTUATION = ("~", "`", " ")

# One uppercase, ten lowercase and one digit. Appending any member of
# SPECIALS clears every rule at exactly MIN_LENGTH characters.
THREE_CLASSES = "Abcdefghij1"
COMPLIANT = THREE_CLASSES + "!"

ELEVEN_CHARACTERS = "Abcdefghi1!"
MISSING_UPPERCASE = "abcdefghij1!"
MISSING_LOWERCASE = "ABCDEFGHIJ1!"
MISSING_DIGIT = "Abcdefghijk!"
MISSING_SPECIAL = "Abcdefghij12"
EMPTY = ""

# SEC-04: 72-byte ceiling, not 72 characters
AT_BYTE_CEILING = COMPLIANT + "x" * 60
ONE_BYTE_OVER_CEILING = COMPLIANT + "x" * 61

# 43 characters, 74 UTF-8 bytes. U+00E9 occupies two bytes.
ACCENTED_OVER_CEILING = COMPLIANT + "\u00e9" * 31
ACCENTED_BYTES = 74

# 28 characters, 76 UTF-8 bytes. U+1F600 occupies four bytes.
EMOJI_OVER_CEILING = COMPLIANT + "\U0001f600" * 16
EMOJI_BYTES = 76

# SEC-04: one table feeds both the HTTP cases and the schema cases
REJECTED_CASES = (
    ("eleven_characters", ELEVEN_CHARACTERS),
    ("empty", EMPTY),
    ("missing_uppercase", MISSING_UPPERCASE),
    ("missing_lowercase", MISSING_LOWERCASE),
    ("missing_digit", MISSING_DIGIT),
    ("missing_special", MISSING_SPECIAL),
    ("one_byte_over_ceiling", ONE_BYTE_OVER_CEILING),
    ("accented_over_ceiling", ACCENTED_OVER_CEILING),
    ("emoji_over_ceiling", EMOJI_OVER_CEILING),
    ("tilde_only", THREE_CLASSES + "~"),
    ("backtick_only", THREE_CLASSES + "`"),
    ("space_only", THREE_CLASSES + " "),
)

REJECTED_PARAMS = [
    pytest.param(value, id=name) for name, value in REJECTED_CASES
]

# An empty value is a substring of every response body. ECHO_PARAMS
# carries the non-empty values.
ECHO_PARAMS = [
    pytest.param(value, id=name) for name, value in REJECTED_CASES if value
]

MISSING_CLASS_PARAMS = [
    pytest.param(MISSING_UPPERCASE, id="missing_uppercase"),
    pytest.param(MISSING_LOWERCASE, id="missing_lowercase"),
    pytest.param(MISSING_DIGIT, id="missing_digit"),
    pytest.param(MISSING_SPECIAL, id="missing_special"),
]

MULTIBYTE_PARAMS = [
    pytest.param(ACCENTED_OVER_CEILING, ACCENTED_BYTES, id="accented"),
    pytest.param(EMOJI_OVER_CEILING, EMOJI_BYTES, id="emoji"),
]

SPECIAL_PARAMS = [
    pytest.param(THREE_CLASSES + character, id="u%04x" % ord(character))
    for character in SPECIALS
]

# SEC-04: the modular-crypt identifier of the scheme AAP 0.7.1 pins, and
# the smallest work factor that scheme may be configured with
BCRYPT_IDENTIFIER = "2b"
MIN_BCRYPT_COST = 12

# SEC-04: a second address for the salting case
SECOND_SCHEMA_EMAIL = "policy-probe-two@example.com"


def _register(client, email, password):
    return client.post(
        REGISTER_PATH, json={"email": email, "password": password}
    )


def _user_row_count(session, email):
    # models.py:8 names the table; the bound parameter keeps the address
    # out of the statement text.
    return session.execute(
        text("SELECT COUNT(*) FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


def _stored_password_hash(session, email):
    # SEC-04: reads the column the route wrote, so the assertion covers
    # what an attacker reaching the table would find
    return session.execute(
        text("SELECT hashed_password FROM users WHERE email = :email"),
        {"email": email},
    ).scalar()


def _modular_crypt_parts(stored):
    # SEC-04: a modular-crypt hash is $identifier$cost$salt-and-digest
    assert stored.startswith("$"), stored
    identifier, cost, remainder = stored[1:].split("$", 2)
    return identifier, cost, remainder


def test_special_set_mirrors_the_client_rule():
    """The server set holds the same 30 characters as validators.ts:23.

    Tilde, backtick and space stay outside it, so the rule names an
    explicit set and not any punctuation.
    """
    assert len(SPECIALS) == SPECIAL_COUNT
    assert len(set(SPECIALS)) == SPECIAL_COUNT
    for character in EXCLUDED_PUNCTUATION:
        assert character not in SPECIALS


def test_compliant_password_registers(client, db_session, unique_email):
    """A compliant password at the minimum length registers.

    The account row reaches the database.
    """
    assert len(COMPLIANT) == MIN_LENGTH

    response = _register(client, unique_email, COMPLIANT)

    assert response.status_code == 200
    assert response.json()["user"]["email"] == unique_email
    assert _user_row_count(db_session, unique_email) == 1


def test_password_one_character_short_is_rejected(client, unique_email):
    """Eleven characters fail the length rule.

    All four character classes are present, so length alone decides the
    outcome.
    """
    assert len(ELEVEN_CHARACTERS) == MIN_LENGTH - 1

    response = _register(client, unique_email, ELEVEN_CHARACTERS)

    assert response.status_code == 422
    assert "password" in response.json()["fields"]


@pytest.mark.parametrize("password", MISSING_CLASS_PARAMS)
def test_missing_character_class_is_rejected(client, unique_email, password):
    """A password holding three of the four character classes fails.

    Each value clears the minimum length, so the missing class is the
    only cause.
    """
    assert len(password) >= MIN_LENGTH

    response = _register(client, unique_email, password)

    assert response.status_code == 422
    assert "password" in response.json()["fields"]


def test_empty_password_is_rejected(client, unique_email):
    """An empty password never reaches the hasher."""
    response = _register(client, unique_email, EMPTY)

    assert response.status_code == 422
    assert "password" in response.json()["fields"]


def test_password_at_the_byte_ceiling_registers(
    client, db_session, unique_email
):
    """A password of exactly 72 UTF-8 bytes registers.

    The ceiling sits at the bcrypt limit and no lower.
    """
    assert len(AT_BYTE_CEILING.encode("utf-8")) == MAX_BYTES

    response = _register(client, unique_email, AT_BYTE_CEILING)

    assert response.status_code == 200
    assert _user_row_count(db_session, unique_email) == 1


def test_password_one_byte_over_the_ceiling_is_rejected(client, unique_email):
    """A password of 73 UTF-8 bytes fails the ceiling."""
    assert len(ONE_BYTE_OVER_CEILING.encode("utf-8")) == MAX_BYTES + 1

    response = _register(client, unique_email, ONE_BYTE_OVER_CEILING)

    assert response.status_code == 422
    assert "password" in response.json()["fields"]


@pytest.mark.parametrize("password,expected_bytes", MULTIBYTE_PARAMS)
def test_multibyte_password_over_the_byte_ceiling_is_rejected(
    client, unique_email, password, expected_bytes
):
    """A multibyte password past 72 UTF-8 bytes fails.

    Both values hold fewer than 72 characters, so the ceiling counts
    bytes.
    """
    assert len(password) <= MAX_BYTES
    assert len(password.encode("utf-8")) == expected_bytes
    assert expected_bytes > MAX_BYTES

    response = _register(client, unique_email, password)

    assert response.status_code == 422
    assert "password" in response.json()["fields"]


@pytest.mark.parametrize("password", REJECTED_PARAMS)
def test_rejected_password_creates_no_user_row(
    client, db_session, unique_email, password
):
    """A rejected registration writes no row.

    The policy runs at the request-schema boundary, ahead of the hasher.
    """
    response = _register(client, unique_email, password)

    assert response.status_code == 422
    assert _user_row_count(db_session, unique_email) == 0


@pytest.mark.parametrize("password", ECHO_PARAMS)
def test_rejection_does_not_echo_the_submitted_password(
    client, unique_email, password
):
    """The 422 body names the rejected field and withholds the value.

    An echoed password would reach client logs and proxy records.
    """
    response = _register(client, unique_email, password)

    assert response.status_code == 422
    assert "password" in response.json()["fields"]
    assert password not in response.text


@pytest.mark.parametrize("password", SPECIAL_PARAMS)
def test_each_special_character_satisfies_the_policy(password):
    """Each of the 30 characters satisfies the special-character rule."""
    model = UserCreate(email=SCHEMA_EMAIL, password=password)

    assert model.password == password


@pytest.mark.parametrize("character", EXCLUDED_PUNCTUATION)
def test_punctuation_outside_the_set_fails_the_policy(character):
    """Tilde, backtick and space fail the special-character rule."""
    with pytest.raises(ValidationError) as failure:
        UserCreate(email=SCHEMA_EMAIL, password=THREE_CLASSES + character)

    assert failure.value.errors()[0]["loc"] == ("password",)


@pytest.mark.parametrize("password", REJECTED_PARAMS)
def test_schema_rejects_every_policy_violation(password):
    """UserCreate raises on every rejected value.

    The error points at the password field.
    """
    with pytest.raises(ValidationError) as failure:
        UserCreate(email=SCHEMA_EMAIL, password=password)

    assert failure.value.errors()[0]["loc"] == ("password",)


def test_the_stored_secret_is_a_bcrypt_hash(
    client, db_session, unique_email
):
    """Registration stores a bcrypt hash at the pinned work factor.

    The 72-byte ceiling every case above asserts is the bcrypt input
    limit, so a different scheme would leave the whole policy arbitrary.
    A reversible or fast digest would also hand an attacker who reads
    one table every password in it (CWE-916).
    """
    response = _register(client, unique_email, COMPLIANT)
    assert response.status_code == 200

    stored = _stored_password_hash(db_session, unique_email)
    assert stored

    # SEC-04: the submitted value is not what the row holds, and the
    # hash is not what the response returns
    assert stored != COMPLIANT
    assert COMPLIANT not in stored
    assert stored not in response.text

    # SEC-04: the pinned scheme, at or above the pinned work factor
    identifier, cost, remainder = _modular_crypt_parts(stored)
    assert identifier == BCRYPT_IDENTIFIER
    assert cost.isdigit(), cost
    assert int(cost) >= MIN_BCRYPT_COST
    assert remainder

    # SEC-04: the hash verifies the password it was made from and
    # nothing else
    assert verify_password(COMPLIANT, stored)
    assert not verify_password(COMPLIANT + "x", stored)


def test_one_password_stored_twice_yields_two_hashes(
    client, db_session, unique_email
):
    """Two accounts sharing a password store different hashes.

    Equal hashes would let one cracked password unlock every account
    that reused it, and would make the column a lookup table (CWE-759).
    """
    second_email = SECOND_SCHEMA_EMAIL

    assert _register(client, unique_email, COMPLIANT).status_code == 200
    assert _register(client, second_email, COMPLIANT).status_code == 200

    first = _stored_password_hash(db_session, unique_email)
    second = _stored_password_hash(db_session, second_email)

    # SEC-04: a per-row salt makes the two hashes differ
    assert first and second
    assert first != second

    # SEC-04: both still verify the shared password
    assert verify_password(COMPLIANT, first)
    assert verify_password(COMPLIANT, second)
