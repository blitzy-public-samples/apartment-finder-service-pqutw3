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
* the revision identifiers and the administrator address and role the
  script holds are the values the revisions themselves declare
* the script parses, and its whole top-level declaration block executes
  under the same shell options the script sets

The two executing cases require ``bash`` and are skipped where it is
absent. The four static cases run on every host, with no shell.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import re
import shutil
import subprocess

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from conftest import ALEMBIC_INI, REPO_ROOT

#: Script under test.
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup_dev_environment.sh"

#: Longest either executing case waits for bash, in seconds.
SHELL_TIMEOUT_SECONDS = 60

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
