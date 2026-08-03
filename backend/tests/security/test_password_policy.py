"""SEC-04 regression tests for the server-side password policy.

Registration cases reach the policy through ``POST /auth/register``,
whose body FastAPI validates against ``UserCreate`` before the route
hashes anything. ``frontend/src/utils/validators.ts`` carries the
matching client-side character set.

Login cases pin the other edge of the policy. ``UserLogin`` carries no
policy rule: an account whose credential predates the policy still
authenticates, and a shape the hasher itself refuses receives the
counted uniform 401 that a wrong secret receives.

The cases run at two layers. The HTTP layer pins the status code, the
field name and the absence of any database row. The schema layer pins
the character set and reports a direct failure when a rule moves.

The stored value is checked too. Every ceiling below is a bcrypt input
limit, so the scheme that produced the hash is covered by these cases.
"""
import logging
import re
from datetime import datetime
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import text

from backend.app.api.endpoints import auth as auth_endpoint
from backend.app.core.security import get_password_hash, verify_password
from backend.app.schema.user import (
    PASSWORD_DIGITS,
    PASSWORD_LOWERCASE,
    PASSWORD_MAX_BYTES,
    PASSWORD_MIN_LENGTH,
    PASSWORD_SPECIAL_CHARACTERS,
    PASSWORD_UPPERCASE,
    UserCreate,
    UserLogin,
)

# There is no /api prefix: router.py applies /auth and main.py includes
# the router without one.
REGISTER_PATH = "/auth/register"

SCHEMA_EMAIL = "policy-probe@example.com"

MIN_LENGTH = 12
MAX_BYTES = 72

# SEC-04: 30-character special set mirrors validators.ts:23
SPECIALS = "!@#$%^&*()_+-=[]{};':\"\\|,.<>/?"
SPECIAL_COUNT = 30

# SEC-04: the authoritative client rule the server policy mirrors. The
# parity cases read it from disk, through a path resolved from this file.
CLIENT_VALIDATOR = (
    Path(__file__).resolve().parents[3]
    / "frontend" / "src" / "utils" / "validators.ts"
)

# The four class rules and the length rule validators.ts declares, named
# by the identifier each is assigned to
CLIENT_UPPERCASE_RULE = "hasUppercase"
CLIENT_LOWERCASE_RULE = "hasLowercase"
CLIENT_DIGIT_RULE = "hasNumber"
CLIENT_SPECIAL_RULE = "hasSpecialChar"
CLIENT_LENGTH_RULE = "minLength"

# validators.ts:22 names the digit class by its shorthand rather than by
# an explicit range
CLIENT_DIGIT_SHORTHAND = "\\d"

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
    # SEC-04: reads the column the route wrote; the assertion covers
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


def _client_rule_line(identifier):
    """Return the line of validators.ts that declares one rule."""
    assert CLIENT_VALIDATOR.is_file(), CLIENT_VALIDATOR
    source = CLIENT_VALIDATOR.read_text(encoding="utf-8")
    # the declaration, not the reference the return statement makes to it
    declaration = "const {0}".format(identifier)
    matches = [line for line in source.splitlines() if declaration in line]
    # a rule declared twice would make the parse below ambiguous
    assert len(matches) == 1, (identifier, matches)
    return matches[0]


def _client_regex_source(identifier):
    """Return the source of the regular expression one rule tests with."""
    line = _client_rule_line(identifier)
    opened = line.index("/")
    index = opened + 1
    while index < len(line):
        character = line[index]
        if character == "\\":
            # a backslash escapes the next character, including a slash
            index += 2
            continue
        if character == "/":
            return line[opened + 1:index]
        index += 1
    raise AssertionError("unterminated expression: {0}".format(line))


def _client_class_members(source):
    """Return every character one bracketed class admits, in order."""
    assert source.startswith("[") and source.endswith("]"), source
    body = source[1:-1]
    members = []
    index = 0
    while index < len(body):
        character = body[index]
        if character == "\\":
            members.append(body[index + 1])
            index += 2
            continue
        if character == "-" and members and index + 1 < len(body):
            # an unescaped hyphen between two members names a range
            first = ord(members.pop())
            last = ord(body[index + 1])
            members.extend(chr(code) for code in range(first, last + 1))
            index += 2
            continue
        members.append(character)
        index += 1
    return members


def test_special_set_mirrors_the_client_rule():
    """The server set holds the same characters validators.ts:23 does.

    The client file is read and its character class parsed, so a
    character added to or dropped from either side fails here.

    Tilde, backtick and space stay outside the set on both sides, so the
    rule names an explicit set and not any punctuation.
    """
    parsed = _client_class_members(
        _client_regex_source(CLIENT_SPECIAL_RULE)
    )

    # the class names each character once, so a duplicate on either side
    # is a drift rather than a harmless repeat
    assert len(parsed) == SPECIAL_COUNT, "".join(parsed)
    assert len(set(parsed)) == SPECIAL_COUNT, "".join(parsed)

    # SEC-04: client, server and this module hold one set between them
    assert set(parsed) == set(PASSWORD_SPECIAL_CHARACTERS)
    assert set(parsed) == set(SPECIALS)
    assert len(PASSWORD_SPECIAL_CHARACTERS) == SPECIAL_COUNT
    assert len(SPECIALS) == SPECIAL_COUNT

    for character in EXCLUDED_PUNCTUATION:
        assert character not in parsed
        assert character not in PASSWORD_SPECIAL_CHARACTERS
        assert character not in SPECIALS


def test_length_and_class_rules_mirror_the_client_rule():
    """Every other policy rule the client declares holds on the server.

    validators.ts:19-22 carries the minimum length and the uppercase,
    lowercase and digit classes. Each is read from that file and compared
    against the constant the server validator applies, so a rule relaxed
    on one side fails here rather than passing on both.
    """
    length_rule = _client_rule_line(CLIENT_LENGTH_RULE)
    declared = re.search(
        r"const\s+minLength\s*=\s*(\d+)\s*;", length_rule
    )
    assert declared is not None, length_rule

    # SEC-04: one minimum length across client, server and this module
    assert int(declared.group(1)) == PASSWORD_MIN_LENGTH
    assert MIN_LENGTH == PASSWORD_MIN_LENGTH

    uppercase = _client_class_members(
        _client_regex_source(CLIENT_UPPERCASE_RULE)
    )
    lowercase = _client_class_members(
        _client_regex_source(CLIENT_LOWERCASE_RULE)
    )
    assert "".join(uppercase) == PASSWORD_UPPERCASE
    assert "".join(lowercase) == PASSWORD_LOWERCASE

    # the client names the digit class by shorthand, so the comparison is
    # against what that shorthand admits
    assert _client_regex_source(CLIENT_DIGIT_RULE) == CLIENT_DIGIT_SHORTHAND
    assert PASSWORD_DIGITS == "0123456789"

    # SEC-04: the byte ceiling is the one rule the server adds. A browser
    # cannot see the hasher, so validators.ts declares no counterpart and
    # this module pins the server constant alone.
    assert MAX_BYTES == PASSWORD_MAX_BYTES
    assert "72" not in _client_rule_line(CLIENT_LENGTH_RULE)


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
    """The 422 body names the password field and omits the submitted value."""
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


# ---------------------------------------------------------------------
# SEC-04: the policy governs registration only. A credential minted
# before it reaches authentication and receives the uniform 401.
# ---------------------------------------------------------------------
LOGIN_PATH = "/auth/login"

# The frozen login response body, set in auth.py
LOGIN_BODY_KEYS = {"access_token", "token_type"}

# The shared error envelope every handler in main.py emits
ENVELOPE_KEYS = {"detail", "error_id", "fields"}

# The one raised detail the credential path logs for every refusal
UNIFORM_LOGIN_DETAIL = "Incorrect email or password"

# Shapes the hasher itself refuses: bcrypt rejects a NUL byte and
# passlib caps a secret at 4096 characters.
NUL_BYTE_PASSWORD = COMPLIANT + "\x00tail"  # blitzy-scan-allow: test fixture
PAST_PASSLIB_CEILING = "A" * 5000
UNPARSEABLE_STORED_HASH = "not-a-bcrypt-digest"

LEGACY_CREDENTIAL_PARAMS = [
    pytest.param(ONE_BYTE_OVER_CEILING, id="one_byte_over_ceiling"),
    pytest.param(ACCENTED_OVER_CEILING, id="accented_over_ceiling"),
    pytest.param(EMOJI_OVER_CEILING, id="emoji_over_ceiling"),
    pytest.param(THREE_CLASSES + "~", id="tilde_only"),
    pytest.param(ELEVEN_CHARACTERS, id="eleven_characters"),
]

HASHER_REFUSAL_PARAMS = [
    pytest.param(NUL_BYTE_PASSWORD, id="nul_byte"),
    pytest.param(PAST_PASSLIB_CEILING, id="past_passlib_ceiling"),
]


def _login(client, email, password):
    return client.post(
        LOGIN_PATH, json={"email": email, "password": password}
    )


def _plant_account(session, email, password=None, stored_hash=None):
    """Insert one account row, bypassing the request schema."""
    digest = (
        stored_hash
        if stored_hash is not None
        else get_password_hash(password)
    )
    session.execute(
        text(
            "INSERT INTO users (email, hashed_password, created_at) "
            "VALUES (:email, :digest, :created_at)"
        ),
        {
            "email": email,
            "digest": digest,
            "created_at": datetime.utcnow(),
        },
    )
    session.commit()


def _without_error_id(response):
    body = dict(response.json())
    body.pop("error_id", None)
    return body


def test_login_schema_admits_a_credential_the_policy_rejects():
    """UserLogin accepts a value UserCreate refuses.

    The byte ceiling and the character classes govern registration. A
    stored credential minted before them stays usable.
    """
    with pytest.raises(ValidationError):
        UserCreate(email=SCHEMA_EMAIL, password=ONE_BYTE_OVER_CEILING)

    model = UserLogin(email=SCHEMA_EMAIL, password=ONE_BYTE_OVER_CEILING)

    assert model.password == ONE_BYTE_OVER_CEILING


@pytest.mark.parametrize("password", LEGACY_CREDENTIAL_PARAMS)
def test_a_credential_predating_the_policy_authenticates(
    client, db_session, unique_email, password
):
    """An account the policy would now refuse still logs in."""
    _plant_account(db_session, unique_email, password=password)

    response = _login(client, unique_email, password)

    assert response.status_code == 200, response.text
    # SEC-06: the frozen login body is unchanged
    assert set(response.json()) == LOGIN_BODY_KEYS


@pytest.mark.parametrize("password", HASHER_REFUSAL_PARAMS)
def test_a_shape_the_hasher_refuses_returns_the_uniform_401(
    client, db_session, unique_email, password
):
    """A refused shape answers 401, never 500 and never 422."""
    _plant_account(db_session, unique_email, password=COMPLIANT)

    refused = _login(client, unique_email, password)
    wrong_secret = _login(client, unique_email, COMPLIANT + "z")

    assert refused.status_code == 401, refused.text
    assert wrong_secret.status_code == 401
    assert set(refused.json()) == ENVELOPE_KEYS
    # SEC-08: one reply covers a refused shape and a wrong secret
    assert _without_error_id(refused) == _without_error_id(wrong_secret)
    assert password not in refused.text


def test_an_unparseable_stored_hash_returns_the_uniform_401(
    client, db_session, unique_email
):
    """A stored digest the hasher cannot parse answers 401, never 500."""
    _plant_account(
        db_session, unique_email, stored_hash=UNPARSEABLE_STORED_HASH
    )

    response = _login(client, unique_email, COMPLIANT)

    assert response.status_code == 401, response.text
    assert set(response.json()) == ENVELOPE_KEYS
    assert UNPARSEABLE_STORED_HASH not in response.text


def test_a_refused_shape_is_counted_against_the_account(
    client, db_session, unique_email
):
    """A hasher refusal consumes one attempt from the account counter."""
    _plant_account(db_session, unique_email, password=COMPLIANT)
    account_key = auth_endpoint._account_key(unique_email)

    response = _login(client, unique_email, NUL_BYTE_PASSWORD)

    assert response.status_code == 401
    # SEC-07: the refusal is a counted attempt, not a free probe
    assert auth_endpoint._login_failures[account_key][0] == 1


def test_the_refusal_reaches_the_log_under_the_client_reference(
    client, db_session, unique_email, caplog
):
    """One record ties the refusal to the reference the caller holds."""
    caplog.set_level(logging.WARNING)
    _plant_account(db_session, unique_email, password=COMPLIANT)

    response = _login(client, unique_email, NUL_BYTE_PASSWORD)

    assert response.status_code == 401
    error_id = response.json()["error_id"]
    matching = [
        record.getMessage()
        for record in caplog.records
        if error_id in record.getMessage()
    ]
    assert len(matching) == 1
    # SEC-08: the record names the refusing hasher error; the reply does not
    assert "hasher=" in matching[0]
    assert UNIFORM_LOGIN_DETAIL in matching[0]
    assert UNIFORM_LOGIN_DETAIL not in response.text
    # SEC-07: no submitted secret and no address reach the record
    assert NUL_BYTE_PASSWORD not in matching[0]
    assert unique_email not in matching[0]
