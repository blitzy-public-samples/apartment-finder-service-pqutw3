"""Provisioning the seeded administrator's credential.

``0002_seed_single_admin.py`` grants the administrative role to one address
and stores a value no password produces, so the account holds the role and
cannot authenticate. ``backend/app/core/admin_provisioning.py`` is the one
supported path that gives it a credential.

Every test here starts from the state that revision actually leaves, by
running the revision rather than by constructing a row, so the module is
exercised against the real starting point. The properties asserted are the
ones the account's privilege rests on: only the address the revision names
is ever written, a credential already in place is never replaced without an
explicit request, the credential is held to the policy every account is held
to, exactly one account holds the role afterwards, no role is ever granted,
and no record carries the credential.
"""

import io
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from backend.app.core import admin_provisioning
from backend.app.core.admin_provisioning import (
    ADMIN_EMAIL,
    ADMIN_ROLE,
    LOCKED_CREDENTIAL,
    OUTCOME_PROVISIONED,
    OUTCOME_RESET,
    OUTCOME_UNCHANGED,
    PASSWORD_VARIABLE,
    RESET_VALUE,
    RESET_VARIABLE,
    AdminProvisioningError,
    main,
    provision_admin_credential,
)
from backend.app.core.authorization import Role
from backend.app.core.logging import (
    REDACTION_PLACEHOLDER,
    RedactingFilter,
    RedactingJsonFormatter,
)
from backend.app.core.security import verify_password
from backend.app.db.models import User

#: Credential the provisioning run stores. It satisfies the registration
#: policy: twelve characters or more, within the byte ceiling, and carrying
#: an uppercase letter, a lowercase letter, a digit and a special character.
FIRST_CREDENTIAL = "Adm1n_Seed_Pass!2026"

#: A second acceptable credential, used to tell a replacement apart from a
#: refusal to replace.
SECOND_CREDENTIAL = "Rot4ted_Seed_Pass!2026"

#: Path of the module under test, read by the structural guard below.
MODULE_PATH = (
    Path(__file__).resolve().parents[3]
    / "backend"
    / "app"
    / "core"
    / "admin_provisioning.py"
)


@pytest.fixture
def seeded_admin(db, run_admin_seed) -> User:
    """Return the row revision ``0002`` leaves for the target address."""
    run_admin_seed("upgrade")
    account = db.query(User).filter(User.email == ADMIN_EMAIL).one()
    return account


@pytest.fixture
def supplied_credential(monkeypatch):
    """Return a callable that places a credential in the environment."""

    def supply(value):
        if value is None:
            monkeypatch.delenv(PASSWORD_VARIABLE, raising=False)
        else:
            monkeypatch.setenv(PASSWORD_VARIABLE, value)

    monkeypatch.delenv(RESET_VARIABLE, raising=False)
    return supply


@pytest.fixture
def requested_reset(monkeypatch):
    """Return a callable that sets the reset request to a given value."""

    def request(value):
        if value is None:
            monkeypatch.delenv(RESET_VARIABLE, raising=False)
        else:
            monkeypatch.setenv(RESET_VARIABLE, value)

    return request


def _stored(db) -> User:
    """Return the target row as it is currently stored."""
    db.expire_all()
    return db.query(User).filter(User.email == ADMIN_EMAIL).one()


class TestStartingState:
    """The state the grant revision leaves, which this module addresses."""

    def test_the_seeded_account_holds_the_role(self, db, seeded_admin):
        assert seeded_admin.role == ADMIN_ROLE
        assert seeded_admin.role == Role.ADMIN.value

    def test_the_seeded_account_cannot_authenticate(self, seeded_admin):
        assert seeded_admin.hashed_password == LOCKED_CREDENTIAL
        assert verify_password(FIRST_CREDENTIAL, LOCKED_CREDENTIAL) is False
        assert verify_password(LOCKED_CREDENTIAL, LOCKED_CREDENTIAL) is False

    def test_the_module_addresses_the_revision_s_address(
        self, admin_seed_revision
    ):
        assert ADMIN_EMAIL == admin_seed_revision.ADMIN_EMAIL
        assert ADMIN_ROLE == admin_seed_revision.ADMIN_ROLE
        assert LOCKED_CREDENTIAL == admin_seed_revision.LOCKED_CREDENTIAL


class TestProvisioning:
    """Replacing the locked marker with a usable credential."""

    def test_the_locked_marker_is_replaced(self, db, seeded_admin):
        outcome = provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()

        assert outcome == OUTCOME_PROVISIONED
        stored = _stored(db)
        assert stored.hashed_password != LOCKED_CREDENTIAL
        assert verify_password(FIRST_CREDENTIAL, stored.hashed_password)

    def test_the_credential_is_read_from_the_environment(
        self, db, seeded_admin, supplied_credential
    ):
        supplied_credential(FIRST_CREDENTIAL)

        assert provision_admin_credential(db) == OUTCOME_PROVISIONED
        db.commit()
        assert verify_password(FIRST_CREDENTIAL, _stored(db).hashed_password)

    def test_the_stored_hash_is_a_bcrypt_hash(self, db, seeded_admin):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()

        assert _stored(db).hashed_password.startswith("$2b$")

    def test_the_role_is_unchanged(self, db, seeded_admin):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()

        assert _stored(db).role == ADMIN_ROLE

    def test_the_lockout_state_is_cleared(self, db, seeded_admin):
        seeded_admin.failed_login_attempts = 5
        seeded_admin.locked_until = datetime.now(timezone.utc) + timedelta(
            minutes=15
        )
        db.commit()

        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()

        stored = _stored(db)
        assert stored.failed_login_attempts == 0
        assert stored.locked_until is None

    def test_no_other_account_is_touched(
        self, db, seeded_admin, user_factory, password_hash
    ):
        others = [
            user_factory("first@example.com", Role.REGISTERED),
            user_factory("second@example.com", Role.PREMIUM),
            user_factory("third@example.com", Role.GUEST),
        ]
        addresses = [account.email for account in others]

        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        db.expire_all()

        for address in addresses:
            account = db.query(User).filter(User.email == address).one()
            assert account.hashed_password == password_hash
            assert account.role != ADMIN_ROLE


class TestIdempotence:
    """A repeated run leaves a credential already in place alone."""

    def test_a_second_run_reports_unchanged(self, db, seeded_admin):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        first = _stored(db).hashed_password

        outcome = provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()

        assert outcome == OUTCOME_UNCHANGED
        assert _stored(db).hashed_password == first

    def test_a_second_run_does_not_apply_a_different_credential(
        self, db, seeded_admin
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()

        outcome = provision_admin_credential(db, SECOND_CREDENTIAL)
        db.commit()

        assert outcome == OUTCOME_UNCHANGED
        stored = _stored(db).hashed_password
        assert verify_password(FIRST_CREDENTIAL, stored)
        assert verify_password(SECOND_CREDENTIAL, stored) is False

    def test_the_unchanged_run_reads_no_credential(
        self, db, seeded_admin, supplied_credential
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        supplied_credential(None)

        assert provision_admin_credential(db, FIRST_CREDENTIAL) == (
            OUTCOME_UNCHANGED
        )


class TestReset:
    """Replacing a credential already in place, on an explicit request."""

    def test_a_reset_replaces_the_credential(
        self, db, seeded_admin, requested_reset
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        requested_reset(RESET_VALUE)

        outcome = provision_admin_credential(db, SECOND_CREDENTIAL)
        db.commit()

        assert outcome == OUTCOME_RESET
        stored = _stored(db).hashed_password
        assert verify_password(SECOND_CREDENTIAL, stored)
        assert verify_password(FIRST_CREDENTIAL, stored) is False

    def test_a_reset_from_the_locked_marker_reports_provisioned(
        self, db, seeded_admin, requested_reset
    ):
        requested_reset(RESET_VALUE)

        assert provision_admin_credential(db, FIRST_CREDENTIAL) == (
            OUTCOME_PROVISIONED
        )

    @pytest.mark.parametrize("declared", ["TRUE", " true ", "True"])
    def test_the_request_is_read_case_insensitively_and_trimmed(
        self, db, seeded_admin, requested_reset, declared
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        requested_reset(declared)

        assert provision_admin_credential(db, SECOND_CREDENTIAL) == (
            OUTCOME_RESET
        )

    @pytest.mark.parametrize(
        "declared", ["false", "1", "yes", "on", "", "  ", "reset", None]
    )
    def test_any_other_value_is_not_a_request(
        self, db, seeded_admin, requested_reset, declared
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        requested_reset(declared)

        assert provision_admin_credential(db, SECOND_CREDENTIAL) == (
            OUTCOME_UNCHANGED
        )


class TestCredentialPolicy:
    """The credential is held to the policy every account is held to."""

    def test_an_absent_credential_is_refused(
        self, db, seeded_admin, supplied_credential
    ):
        supplied_credential(None)

        with pytest.raises(AdminProvisioningError) as refusal:
            provision_admin_credential(db)

        assert PASSWORD_VARIABLE in str(refusal.value)
        assert _stored(db).hashed_password == LOCKED_CREDENTIAL

    def test_an_empty_credential_is_refused(
        self, db, seeded_admin, supplied_credential
    ):
        supplied_credential("")

        with pytest.raises(AdminProvisioningError):
            provision_admin_credential(db)

        assert _stored(db).hashed_password == LOCKED_CREDENTIAL

    @pytest.mark.parametrize(
        "credential",
        [
            "Sh0rt!aA",
            "alllowercase1!x",
            "ALLUPPERCASE1!X",
            "NoDigitsHere!xY",
            "NoSpecial1CharXy",
            "A1!" + "a" * 70,
        ],
        ids=[
            "below-the-length-floor",
            "no-uppercase",
            "no-lowercase",
            "no-digit",
            "no-special-character",
            "above-the-byte-ceiling",
        ],
    )
    def test_a_credential_outside_the_policy_is_refused(
        self, db, seeded_admin, credential
    ):
        with pytest.raises(AdminProvisioningError) as refusal:
            provision_admin_credential(db, credential)

        assert PASSWORD_VARIABLE in str(refusal.value)
        assert _stored(db).hashed_password == LOCKED_CREDENTIAL

    def test_the_refusal_does_not_repeat_the_credential(
        self, db, seeded_admin
    ):
        credential = "Sh0rt!aA"

        with pytest.raises(AdminProvisioningError) as refusal:
            provision_admin_credential(db, credential)

        assert credential not in str(refusal.value)

    def test_a_credential_at_the_length_floor_is_accepted(
        self, db, seeded_admin
    ):
        credential = "Aa1!aaaaaaaa"
        assert len(credential) == 12

        assert provision_admin_credential(db, credential) == (
            OUTCOME_PROVISIONED
        )


class TestNoEscalationPath:
    """The module sets a credential and grants no privilege."""

    def test_an_account_without_the_role_is_refused(
        self, db, user_factory, password_hash
    ):
        user_factory(ADMIN_EMAIL, Role.REGISTERED)

        with pytest.raises(AdminProvisioningError) as refusal:
            provision_admin_credential(db, FIRST_CREDENTIAL)

        assert Role.REGISTERED.value in str(refusal.value)
        stored = _stored(db)
        assert stored.role == Role.REGISTERED.value
        assert stored.hashed_password == password_hash

    @pytest.mark.parametrize(
        "role", [Role.GUEST, Role.REGISTERED, Role.PREMIUM]
    )
    def test_no_lesser_role_is_promoted(self, db, user_factory, role):
        user_factory(ADMIN_EMAIL, role)

        with pytest.raises(AdminProvisioningError):
            provision_admin_credential(db, FIRST_CREDENTIAL)

        assert _stored(db).role == role.value

    def test_an_absent_account_is_refused(self, db):
        with pytest.raises(AdminProvisioningError) as refusal:
            provision_admin_credential(db, FIRST_CREDENTIAL)

        assert ADMIN_EMAIL in str(refusal.value)
        assert db.query(User).count() == 0

    def test_the_module_never_writes_the_role_column(self):
        source = MODULE_PATH.read_text(encoding="utf-8")
        code = "\n".join(
            line for line in source.splitlines()
            if not line.lstrip().startswith("#")
        )

        assert re.search(r"\.role\s*=[^=]", code) is None
        assert "ADMIN_ROLE =" in source


class TestSingleAdministratorPostcondition:
    """Exactly one account holds the role once the run has finished."""

    def test_a_successful_run_leaves_one_administrator(
        self, db, seeded_admin
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()

        holders = db.query(User).filter(User.role == ADMIN_ROLE).all()
        assert [account.email for account in holders] == [ADMIN_EMAIL]

    def test_a_second_administrator_fails_the_postcondition(
        self, db, seeded_admin, user_factory
    ):
        user_factory("other-admin@example.com", Role.ADMIN)

        with pytest.raises(AdminProvisioningError) as refusal:
            provision_admin_credential(db, FIRST_CREDENTIAL)

        assert "post-condition" in str(refusal.value)

    def test_the_failed_postcondition_leaves_no_credential(
        self, db, seeded_admin, user_factory
    ):
        user_factory("other-admin@example.com", Role.ADMIN)

        with pytest.raises(AdminProvisioningError):
            provision_admin_credential(db, FIRST_CREDENTIAL)
        db.rollback()

        assert _stored(db).hashed_password == LOCKED_CREDENTIAL

    def test_the_postcondition_is_asserted_on_an_unchanged_run(
        self, db, seeded_admin, user_factory
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        user_factory("other-admin@example.com", Role.ADMIN)

        with pytest.raises(AdminProvisioningError) as refusal:
            provision_admin_credential(db, FIRST_CREDENTIAL)

        assert "post-condition" in str(refusal.value)


class TestEntryPoint:
    """The behaviour of the command an operator runs."""

    @pytest.fixture
    def entry_point_session(self, db, monkeypatch):
        """Bind the module's session factory to the test session."""
        closed = []

        class Factory:
            def __call__(self):
                return db

        monkeypatch.setattr(admin_provisioning, "SessionLocal", Factory())
        monkeypatch.setattr(
            db, "close", lambda: closed.append(True), raising=False
        )
        return closed

    def test_a_successful_run_exits_zero_and_commits(
        self, db, seeded_admin, entry_point_session, supplied_credential,
        capsys,
    ):
        supplied_credential(FIRST_CREDENTIAL)

        assert main() == 0

        assert verify_password(FIRST_CREDENTIAL, _stored(db).hashed_password)
        assert OUTCOME_PROVISIONED in capsys.readouterr().out

    def test_a_refused_run_exits_one_and_writes_no_credential(
        self, db, seeded_admin, entry_point_session, supplied_credential,
        capsys,
    ):
        supplied_credential(None)

        assert main() == 1

        assert _stored(db).hashed_password == LOCKED_CREDENTIAL
        assert PASSWORD_VARIABLE in capsys.readouterr().err

    def test_an_argument_is_refused(
        self, db, seeded_admin, entry_point_session, supplied_credential,
        capsys,
    ):
        supplied_credential(FIRST_CREDENTIAL)

        assert main(("Adm1n_Seed_Pass!2026",)) == 1

        assert _stored(db).hashed_password == LOCKED_CREDENTIAL
        assert PASSWORD_VARIABLE in capsys.readouterr().err

    def test_the_session_is_closed(
        self, db, seeded_admin, entry_point_session, supplied_credential
    ):
        supplied_credential(FIRST_CREDENTIAL)

        main()

        assert entry_point_session == [True]

    def test_a_repeated_run_exits_zero(
        self, db, seeded_admin, entry_point_session, supplied_credential,
        capsys,
    ):
        supplied_credential(FIRST_CREDENTIAL)
        assert main() == 0
        capsys.readouterr()

        assert main() == 0
        assert OUTCOME_UNCHANGED in capsys.readouterr().out

    def test_an_unexpected_failure_rolls_back_and_propagates(
        self, db, seeded_admin, entry_point_session, supplied_credential,
        monkeypatch,
    ):
        """A fault that is not a refusal must not be reported as success."""
        supplied_credential(FIRST_CREDENTIAL)
        rolled_back = []
        monkeypatch.setattr(
            db, "rollback", lambda: rolled_back.append(True), raising=False
        )

        def fail(*args, **kwargs):
            raise RuntimeError("the database went away")

        monkeypatch.setattr(
            admin_provisioning, "provision_admin_credential", fail
        )

        with pytest.raises(RuntimeError, match="went away"):
            main()

        assert rolled_back == [True]
        assert entry_point_session == [True]


class TestObservability:
    """Every outcome is recorded, and no record carries the credential.

    The records are read through the redacting filter and the JSON
    formatter attached to the module's own logger, which is how the
    application emits them. The shared redactor treats an address as
    sensitive, so a record identifies its run by the outcome and the
    administrator count it carries.
    """

    @pytest.fixture
    def emitted(self):
        """Yield a callable returning the records emitted so far."""
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setFormatter(RedactingJsonFormatter())
        handler.addFilter(RedactingFilter())
        logger = admin_provisioning.logger
        previous_handlers = list(logger.handlers)
        previous_level = logger.level
        previous_propagate = logger.propagate
        logger.handlers = [handler]
        logger.propagate = False
        logger.setLevel(logging.DEBUG)

        def records():
            handler.flush()
            return [
                json.loads(line)
                for line in stream.getvalue().splitlines()
                if line.strip()
            ]

        try:
            yield records
        finally:
            logger.handlers = previous_handlers
            logger.propagate = previous_propagate
            logger.setLevel(previous_level)

    def test_the_provisioning_outcome_is_recorded(
        self, db, seeded_admin, emitted
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)

        records = emitted()
        assert [record["context"]["outcome"] for record in records] == [
            OUTCOME_PROVISIONED
        ]
        assert records[0]["level"] == "INFO"

    def test_the_reset_outcome_is_recorded(
        self, db, seeded_admin, emitted, requested_reset
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        requested_reset(RESET_VALUE)

        provision_admin_credential(db, SECOND_CREDENTIAL)

        outcomes = [
            record["context"]["outcome"] for record in emitted()
        ]
        assert outcomes == [OUTCOME_PROVISIONED, OUTCOME_RESET]

    def test_the_unchanged_outcome_names_the_reset_variable(
        self, db, seeded_admin, emitted
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()

        provision_admin_credential(db, FIRST_CREDENTIAL)

        unchanged = [
            record for record in emitted()
            if record["context"]["outcome"] == OUTCOME_UNCHANGED
        ]
        assert len(unchanged) == 1
        message = unchanged[0]["message"]
        assert RESET_VARIABLE in message
        assert repr(RESET_VALUE) in message

    def test_the_logger_name_does_not_depend_on_the_invocation(self):
        assert admin_provisioning.logger.name == (
            "backend.app.core.admin_provisioning"
        )
        assert "__main__" not in admin_provisioning.logger.name

    def test_every_record_is_emitted_under_that_name(
        self, db, seeded_admin, emitted
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)

        for record in emitted():
            assert record["logger"] == admin_provisioning.logger.name

    def test_the_record_carries_the_administrator_count(
        self, db, seeded_admin, emitted
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)

        assert "count is 1" in emitted()[0]["message"]

    def test_the_address_is_redacted_rather_than_disclosed(
        self, db, seeded_admin, emitted
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)

        record = emitted()[0]
        assert ADMIN_EMAIL not in json.dumps(record)
        assert record["context"]["email"] == REDACTION_PLACEHOLDER

    @pytest.mark.parametrize(
        "credential", [FIRST_CREDENTIAL, SECOND_CREDENTIAL]
    )
    def test_no_record_carries_the_credential(
        self, db, seeded_admin, emitted, requested_reset, credential
    ):
        requested_reset(RESET_VALUE)

        provision_admin_credential(db, credential)
        db.commit()

        for record in emitted():
            assert credential not in json.dumps(record)

    def test_no_record_carries_the_stored_hash(
        self, db, seeded_admin, emitted
    ):
        provision_admin_credential(db, FIRST_CREDENTIAL)
        db.commit()
        stored = _stored(db).hashed_password

        for record in emitted():
            assert stored not in json.dumps(record)

    def test_a_refusal_writes_no_record_carrying_the_credential(
        self, db, seeded_admin, emitted
    ):
        weak = "Sh0rt!aA"

        with pytest.raises(AdminProvisioningError):
            provision_admin_credential(db, weak)

        for record in emitted():
            assert weak not in json.dumps(record)
