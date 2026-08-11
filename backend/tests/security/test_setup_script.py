"""Checks over the developer setup script's top-level declarations.

``scripts/setup_dev_environment.sh`` runs under ``set -Eeuo pipefail``, so
a fault in the block of constants it declares before its first function
ends the script before any step of the setup runs. Two such faults are
invisible to ``bash -n``, which parses without executing:

* a name declared ``readonly`` twice -- bash refuses the second
  assignment and returns non-zero, whatever value it carries
* an expansion of a name no longer declared -- ``set -u`` refuses it

What is asserted here:

* no name is declared ``readonly`` more than once
* every capitalised name the script expands is either declared in the
  script or is one of the shell and environment names it deliberately
  reads
* the revision identifiers and the administrator address, role and
  account reference the script holds are the values the revisions
  themselves declare
* nothing the script reports renders the administrator address. The
  address is what the script compares against, so it is held as a
  constant and used in comparisons, while what the script writes to a
  terminal is the same non-reversible reference the grant revision
  records -- so a setup log and a migration record name one account
  without either naming the person
* the script parses, and its whole top-level declaration block executes
  under the same shell options the script sets

A second group of cases covers the script's own contract with whoever
runs it: the arguments it refuses, the inputs it documents, the database
administrator connection it requires before it creates anything, the
alphabet the database password is drawn from, and the agreement between
what it writes and what ``.env.example`` and ``README.md`` say it writes.

The executing cases require ``bash`` and are skipped where it is absent.
Every other case runs on every host, with no shell.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import os
import re
import shutil
import subprocess
import sys

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from conftest import ALEMBIC_INI, REPO_ROOT

#: Script under test.
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup_dev_environment.sh"

#: Files whose description of the environment file the script writes must
#: agree with the script itself.
ENVIRONMENT_EXAMPLE = REPO_ROOT / ".env.example"
README = REPO_ROOT / "README.md"

#: Inputs the usage text is required to document.
DOCUMENTED_INPUTS = (
    "SETUP_DB_ADMIN_USER",
    "SETUP_DB_ADMIN_DB",
    "SETUP_DB_ADMIN_HOST",
    "SETUP_DB_ADMIN_PORT",
    "PYTHON",
)

#: Status the script exits with when it is given an argument.
USAGE_STATUS = 2

#: Characters no password this script generates or accepts may carry.
#: docker compose reads a dollar sign in an environment file as the start
#: of a variable reference and a backslash as an escape, and a quotation
#: mark or a backtick is transformed by a shell that reads the value back.
TRANSFORMED_CHARACTERS = "$\\\"'`"

#: Steps of the script's entry point, in the order it runs them. The
#: administrator connection is checked before the first step that creates,
#: writes or installs anything.
EXPECTED_MAIN_ORDER = (
    "parse_arguments",
    "check_software",
    "check_database_admin_access",
    "setup_virtual_env",
    "install_dependencies",
    "configure_env_vars",
    "init_database",
    "run_migrations",
)

#: Longest a parse or a run of the declaration block alone waits for
#: bash, in seconds. Both complete in a fraction of a second.
SHELL_TIMEOUT_SECONDS = 60

#: Longest a run of the whole script waits for bash, in seconds.
#:
#: A run reaches the step that builds a virtual environment, so its cost
#: is that of a real ``python -m venv`` on the host it runs on rather
#: than of parsing a file. Measured on this repository's Windows
#: verification host, the longest such case takes a little under thirty
#: seconds on an idle machine, and the budget is set an order of
#: magnitude above that so host contention cannot turn a correct case
#: red. Design rationale is recorded in
#: ``docs/security/DECISION_LOG.md``.
SCRIPT_TIMEOUT_SECONDS = 300

#: One ``readonly`` declaration of a capitalised name.
READONLY_DECLARATION = re.compile(
    r"(?m)^\s*readonly\s+([A-Z][A-Z0-9_]*)="
)

#: One assignment to a capitalised name, however it is introduced.
ASSIGNMENT = re.compile(
    r"(?m)^\s*(?:readonly\s+|local\s+|export\s+)?([A-Z][A-Z0-9_]*)="
)

#: One capitalised name introduced as a loop variable.
LOOP_VARIABLE = re.compile(r"(?m)^\s*for\s+([A-Z][A-Z0-9_]*)\s+in\b")

#: One expansion of a capitalised name, braced or bare.
EXPANSION = re.compile(r"\$\{?([A-Z][A-Z0-9_]*)")

#: One shell function definition at the start of a line.
FUNCTION_DEFINITION = re.compile(r"(?m)^([a-z_][a-z0-9_]*)\(\)\s*\{")

#: Capitalised names the script expands without declaring: three the
#: shell maintains, and one a developer may export to name the
#: interpreter to use.
UNDECLARED_NAMES_READ = frozenset(
    {"BASHPID", "BASH_SOURCE", "LINENO", "PYTHON"}
)

#: Shell options the script sets, applied to the declaration block so it
#: is executed under the conditions the script runs under.
SHELL_OPTIONS = "-Eeuo"

#: Names that carry the administrator address: the constant the script
#: declares, the two the embedded interpreters receive it under, and the
#: local one of them binds it to.
ADDRESS_BEARING_NAMES = frozenset(
    {"ADMIN_EMAIL", "ADMIN_SEED_EMAIL", "SETUP_ADMIN_EMAIL", "email"}
)

#: One call that writes to a terminal, in either language the script uses.
REPORTING_CALL = re.compile(r"\b(?:echo|printf|print)\b")

#: A shell line continued onto the next, with the newline it hides. A
#: reporting call and the value it renders are frequently on either side
#: of one, so the logical line is scanned rather than the physical one.
CONTINUATION = re.compile(r"\\\n\s*")


def _script_text():
    """Return the script's source."""
    return SETUP_SCRIPT.read_text(encoding="utf-8")


def _declaration_block():
    """Return the script's source up to its first function definition.

    Everything the script executes before defining a function is a
    declaration. A fault in this block ends the run before any setup step
    is reached.
    """
    text = _script_text()
    first = FUNCTION_DEFINITION.search(text)
    assert first is not None, "the script defines no function"
    return text[: first.start()]


def _revision_module(revision):
    """Return the loaded module of one revision in this repository."""
    directory = ScriptDirectory.from_config(Config(str(ALEMBIC_INI)))
    return directory.get_revision(revision).module


def _constant(text, name):
    """Return the value the script assigns ``name``, unquoted."""
    found = re.search(
        r"(?m)^\s*readonly\s+" + name + r'="?([^"\n]*)"?\s*$', text
    )
    assert found is not None, "the script declares no " + name
    return found.group(1)


def _bash():
    """Return the path of an available bash, or skip the case."""
    executable = shutil.which("bash")
    if executable is None:
        pytest.skip("bash is unavailable on this host")
    return executable


def test_the_script_is_present_and_declares_functions():
    """The script exists and the block boundary is locatable."""
    assert SETUP_SCRIPT.is_file(), SETUP_SCRIPT
    names = FUNCTION_DEFINITION.findall(_script_text())
    for expected in (
        "check_software",
        "install_dependencies",
        "setup_virtual_env",
        "configure_env_vars",
        "init_database",
        "run_migrations",
        "main",
    ):
        assert expected in names, (expected, names)


def test_no_name_is_declared_readonly_twice():
    """A second ``readonly`` assignment would end the script at once."""
    declared = READONLY_DECLARATION.findall(_script_text())
    repeated = sorted(
        set(name for name in declared if declared.count(name) > 1)
    )
    assert repeated == [], repeated
    assert declared, "the script declares no readonly constant"


def test_every_expanded_name_is_declared_or_deliberately_read():
    """No expansion names a constant the script no longer declares."""
    text = _script_text()
    declared = set(ASSIGNMENT.findall(text))
    declared |= set(LOOP_VARIABLE.findall(text))
    declared |= UNDECLARED_NAMES_READ
    dangling = sorted(set(EXPANSION.findall(text)) - declared)
    assert dangling == [], dangling


def test_the_declaration_block_holds_every_constant_it_expands():
    """The block's own expansions resolve inside the block itself."""
    block = _declaration_block()
    declared = set(ASSIGNMENT.findall(block))
    declared |= set(LOOP_VARIABLE.findall(block))
    declared |= UNDECLARED_NAMES_READ
    dangling = sorted(set(EXPANSION.findall(block)) - declared)
    assert dangling == [], dangling


def test_the_revision_constants_name_the_revisions_in_this_repository():
    """The recorded revision identifiers are the revisions themselves."""
    text = _script_text()
    schema = _constant(text, "SCHEMA_REVISION")
    seed = _constant(text, "SEED_REVISION")

    assert _revision_module(schema).revision == schema
    grant = _revision_module(seed)
    assert grant.revision == seed
    assert grant.down_revision == schema


def test_the_administrator_constants_match_the_grant_revision():
    """The address and role the script checks are the granted ones."""
    text = _script_text()
    grant = _revision_module(_constant(text, "SEED_REVISION"))

    assert _constant(text, "ADMIN_EMAIL") == grant.ADMIN_EMAIL
    assert _constant(text, "ADMIN_ROLE") == grant.ADMIN_ROLE


def test_the_administrator_reference_matches_the_grant_revision():
    """The reference the script reports is the one the revision records.

    Both are derived from the same address, so a setup run and a migration
    record can be read against each other. Neither derivation can be
    reversed to the address.
    """
    text = _script_text()
    grant = _revision_module(_constant(text, "SEED_REVISION"))
    reference = _constant(text, "ADMIN_REFERENCE")

    assert reference == grant.ADMIN_REFERENCE
    assert reference == grant.account_reference(grant.ADMIN_EMAIL)
    assert len(reference) == grant.ACCOUNT_REFERENCE_LENGTH
    assert grant.ADMIN_EMAIL not in reference


def _logical_lines():
    """Return the script's lines with continuations joined.

    A shell statement may be spread over several physical lines, and a
    reporting call is often on one while the value it renders is on the
    next. Joining them first is what makes a line-by-line scan sound.
    """
    return CONTINUATION.sub(" ", _script_text()).splitlines()


@pytest.mark.parametrize("name", sorted(ADDRESS_BEARING_NAMES))
def test_no_reported_line_renders_the_administrator_address(name):
    """What the script writes out carries the reference, not the address.

    The address is still held and still compared against -- a comparison
    is not a disclosure. What is asserted is that no statement which
    writes to a terminal reads a name carrying it, in the shell or in
    either embedded interpreter.
    """
    reading = re.compile(r"(?:\$\{?" + name + r"\b|\b" + name + r"\b)")
    rendering = [
        line.strip()
        for line in _logical_lines()
        if REPORTING_CALL.search(line) and reading.search(line)
    ]
    assert rendering == [], rendering


def test_the_address_literal_appears_only_where_it_is_declared():
    """The address is written once, as the constant the script compares."""
    text = _script_text()
    address = _constant(text, "ADMIN_EMAIL")
    carrying = [
        line.strip()
        for line in text.splitlines()
        if address in line
    ]
    assert len(carrying) == 1, carrying
    assert carrying[0].startswith("readonly ADMIN_EMAIL="), carrying[0]


def test_the_script_parses():
    """``bash -n`` accepts the script."""
    completed = subprocess.run(
        [_bash(), "-n", str(SETUP_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=SHELL_TIMEOUT_SECONDS,
    )
    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", "replace"
    )


def test_the_declaration_block_executes_under_the_scripts_options(
    tmp_path,
):
    """Every constant the script declares is assigned exactly once.

    The block is executed rather than parsed, under the script's own
    shell options. A repeated ``readonly`` and an expansion of an absent
    name each end the block with a non-zero status and a message on
    standard error, and both are asserted absent.
    """
    block = tmp_path / "declarations.sh"
    block.write_text(_declaration_block(), encoding="utf-8")

    completed = subprocess.run(
        [_bash(), SHELL_OPTIONS, "pipefail", str(block)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=SHELL_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", "replace"
    )
    assert completed.stderr.decode("utf-8", "replace") == ""


# --- The script's contract with whoever runs it ----------------------------


def _scratch_repository(tmp_path, environment_file=None):
    """Returns a directory the script will treat as its repository root.

    The script resolves every path it reads from its own location rather
    than from the working directory, so a copy of it under
    ``<tmp_path>/scripts`` makes ``<tmp_path>`` the root it consults. That
    is what lets a case decide whether an environment file is present
    instead of inheriting whatever the checkout happens to hold.
    """
    scripts = tmp_path / "scripts"
    scripts.mkdir(parents=True, exist_ok=True)
    copy = scripts / SETUP_SCRIPT.name
    shutil.copyfile(str(SETUP_SCRIPT), str(copy))
    if environment_file is not None:
        (tmp_path / ".env").write_text(environment_file, encoding="utf-8")
    return copy


def _run_script(arguments=(), inputs=None, tmp_path=None, script=None):
    """Runs the setup script and returns the completed process.

    Every case below stops before the first step that creates, writes or
    installs anything, so none of them changes the checkout. A case that
    depends on whether an environment file exists passes ``script`` a copy
    returned by :func:`_scratch_repository`, because the presence of one in
    the checkout would otherwise decide the outcome.
    """
    environment = dict(os.environ)

    for name in DOCUMENTED_INPUTS:
        environment.pop(name, None)

    if inputs:
        environment.update(inputs)

    target = script or SETUP_SCRIPT

    return subprocess.run(
        [_bash(), str(target)] + list(arguments),
        cwd=str(tmp_path or REPO_ROOT),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=SCRIPT_TIMEOUT_SECONDS,
    )


def test_the_script_prints_its_usage_and_exits_zero():
    """``--help`` documents every input and changes nothing."""
    completed = _run_script(arguments=("--help",))
    printed = completed.stdout.decode("utf-8", "replace")

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", "replace"
    )

    for name in DOCUMENTED_INPUTS:
        assert name in printed, name

    assert "CREATEROLE" in printed
    assert "PGPASSWORD" in printed
    assert "!@#^&*()-_=+" in printed


def test_the_script_refuses_a_positional_argument():
    """An argument is refused before any step is reached.

    The script previously accepted and silently ignored any argument, so a
    mistyped invocation still ran the whole setup.
    """
    completed = _run_script(arguments=("staging",))

    assert completed.returncode == USAGE_STATUS
    assert b"staging" in completed.stderr


def _entry_point_body():
    """Returns the body of the script's entry point."""
    text = _script_text()
    start = text.index("\nmain() {")
    return text[start:text.index("\n}\n", start)]


def _flattened(path):
    """Returns one document with every run of whitespace collapsed."""
    return " ".join(path.read_text(encoding="utf-8").split())


def test_the_administrator_connection_is_checked_before_any_side_effect():
    """The database administrator is required before anything is created.

    The database step previously assumed the invoking account could
    connect to PostgreSQL and create roles, and failed only after the
    virtual environment, the dependencies and the environment file had
    already been written.
    """
    body = _entry_point_body()
    order = []

    for step in EXPECTED_MAIN_ORDER:
        assert step in body, step
        order.append(body.index(step))

    assert order == sorted(order), EXPECTED_MAIN_ORDER


#: An environment file whose DATABASE_URL is already configured, so the
#: database step has nothing to create.
CONFIGURED_ENVIRONMENT_FILE = (
    "ENVIRONMENT=local\n"
    "DATABASE_URL=postgresql://apartment_finder:already-set@"
    "localhost:5432/apartment_finder\n"
)

#: An environment file still carrying the template's placeholder, so the
#: database step would create the role and the database.
UNCONFIGURED_ENVIRONMENT_FILE = (
    "ENVIRONMENT=local\n"
    "DATABASE_URL=postgresql://apartment_finder:REPLACE_DB_PASSWORD@"
    "localhost:5432/apartment_finder\n"
)


def _requires_setup_tools():
    """Skips a case that has to run the script end to end."""
    for tool in ("psql", "npm"):
        if shutil.which(tool) is None:
            pytest.skip(tool + " is unavailable on this host")


@pytest.mark.parametrize(
    "environment_file",
    [None, UNCONFIGURED_ENVIRONMENT_FILE],
    ids=["no-environment-file", "placeholder-database-url"],
)
def test_the_script_requires_a_named_database_administrator(
    tmp_path, environment_file
):
    """No administrator named, no database object created.

    The script is run in a scratch repository rather than in the
    checkout. The refusal only applies when the database step has
    something to create, so a checkout that has already been set up
    carries an environment file that sends the script down the other
    branch -- and the case would then run the whole setup instead of
    asserting anything, installing dependencies as a side effect.
    """
    _requires_setup_tools()
    script = _scratch_repository(tmp_path, environment_file)

    # The interpreter running this case is the pinned one, so it is the
    # one offered to the script rather than whatever PATH resolves.
    completed = _run_script(
        inputs={"PYTHON": sys.executable}, script=script
    )
    reported = completed.stderr.decode("utf-8", "replace")

    if "Python 3.9 was not found" in reported:
        pytest.skip("no Python 3.9 interpreter is available on this host")

    assert completed.returncode != 0
    assert "SETUP_DB_ADMIN_USER is not set." in reported
    assert "CREATEROLE" in reported

    # It refused before the first step that writes anything.
    assert not (tmp_path / "venv").exists()


def test_the_script_asks_for_no_administrator_it_has_no_use_for(tmp_path):
    """A configured environment file means nothing has to be created.

    Demanding administrator credentials for work the script will not do
    would have an operator hand over a privileged account for no reason,
    so the check is skipped and says why. This is the branch a checkout
    that has already been set up takes.
    """
    _requires_setup_tools()
    script = _scratch_repository(tmp_path, CONFIGURED_ENVIRONMENT_FILE)

    completed = _run_script(
        inputs={"PYTHON": sys.executable}, script=script
    )
    reported = completed.stderr.decode("utf-8", "replace")
    printed = completed.stdout.decode("utf-8", "replace")

    if "Python 3.9 was not found" in reported:
        pytest.skip("no Python 3.9 interpreter is available on this host")

    assert "SETUP_DB_ADMIN_USER is not set." not in reported
    assert "already names a configured DATABASE_URL" in printed
    assert "no administrator connection is needed" in " ".join(
        printed.split()
    )


def test_every_database_statement_runs_as_the_named_administrator():
    """No statement falls back to the identity of whoever ran the script."""
    text = _script_text()

    assert "psql_admin() {" in text
    assert '--username="${SETUP_DB_ADMIN_USER}"' in text
    assert "--no-password" in text

    # createdb carried no connection options at all, so it connected as
    # the invoking account whatever the administrator named.
    assert re.search(r"(?m)^\s*createdb\b", text) is None

    # psql itself is invoked in exactly one place, the wrapper above, and
    # every statement reaches PostgreSQL through it.
    invocations = [
        line
        for line in text.splitlines()
        if line.strip().startswith(("psql ", "| psql "))
    ]

    assert len(invocations) == 1, invocations

    for line in text.splitlines():
        assert "--dbname=postgres" not in line, line


def test_the_password_alphabet_is_shared_and_carries_nothing_transformed():
    """One alphabet, and no character any reader would transform.

    The password was previously escaped for SQL and percent-encoded for
    the connection URLs but written raw into POSTGRES_PASSWORD, so a value
    carrying a dollar sign left PostgreSQL and the container on different
    passwords.
    """
    text = _script_text()
    declared = _constant(text, "PASSWORD_SPECIAL_CHARACTERS").strip("'")
    embedded = re.search(r'(?m)^SPECIAL = "([^"\n]*)"$', text)

    assert embedded is not None, "the generator declares no alphabet"
    assert declared == embedded.group(1)

    for character in TRANSFORMED_CHARACTERS:
        assert character not in declared, character

    accepted = _constant(text, "PASSWORD_ACCEPTED_FOR_TR").strip("'")

    for character in TRANSFORMED_CHARACTERS:
        assert character not in accepted, character

    assert accepted.endswith("-"), accepted


def test_the_written_environment_file_is_read_back_before_it_is_placed():
    """The three entries carrying the password are compared to it."""
    text = _script_text()
    start = text.index("\ninit_database() {")
    body = text[start:text.index("\n}\n", start)]

    verify = body.index("verify_database_password_round_trip")
    place = body.index('mv "${env_tmp}" "${env_file}"')

    assert verify < place
    assert "POSTGRES_PASSWORD" in body
    assert "COMPOSE_DATABASE_URL" in body
    assert "which a reader of the file transforms" in text


def test_the_template_documents_the_environment_file_the_code_reads():
    """``.env.example`` describes the default the settings class applies.

    It previously said the file was read from the working directory, while
    the settings class resolves an absolute path under the repository root.
    """
    documented = ENVIRONMENT_EXAMPLE.read_text(encoding="utf-8")

    assert "at the repository root, by absolute path" in documented
    assert "reads `.env` from its working\n# directory" not in documented
    assert "whichever directory the process was started in" in documented


def test_the_template_separates_rendering_from_starting():
    """A verbatim copy renders the document but does not start the stack.

    The template said it did both, while the signing key it ships is a
    placeholder that startup refuses in every environment.
    """
    documented = ENVIRONMENT_EXAMPLE.read_text(encoding="utf-8")

    assert "RENDERING IS NOT STARTING" in documented
    assert "renders and starts under either profile" not in documented
    assert "startup refuses in every environment" in documented


def test_the_template_scopes_the_escaping_rule_to_a_hand_written_value():
    """The doubling rule is a rule for a human, not for the script.

    The script refuses a database password carrying a dollar sign, so
    nothing it writes needs escaping, which is what the template now says.
    """
    documented = ENVIRONMENT_EXAMPLE.read_text(encoding="utf-8")

    assert "applies to a value filled in here by hand" in documented
    assert "refuses a" in documented
    assert "need no escaping" in documented


def test_the_readme_documents_the_same_environment_file_semantics():
    """One description of which file is read, in both places."""
    documented = README.read_text(encoding="utf-8")
    flattened = _flattened(README)

    assert 'env_file = ".env"' not in documented
    assert "at the repository root, by absolute path" in flattened
    assert "`ENV_FILE`" in documented
