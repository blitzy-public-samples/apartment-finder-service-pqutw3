"""Startup checks over the developer bootstrap script.

``scripts/setup_dev_environment.sh`` creates a virtual environment,
installs the dependency manifests, writes an environment file carrying a
generated signing key, creates a local database role and database, and
applies the schema revisions. What is asserted here is that the script
*starts*: every check below leaves the environment it is run in
unchanged.

Two checks are made.

* The script is parsed by ``bash -n``, which reports a syntax error
  without executing a statement.
* Every top-level statement is then **executed** by ``bash`` with the
  entry-point invocation removed. That runs the whole file -- the shell
  options, the ``readonly`` declarations, the mutable variable
  assignments, the traps and every function *definition* -- without
  calling a step, so nothing is created, written, installed or dropped.
  The one function that does run is ``cleanup``, which the EXIT trap
  invokes and which removes only the temporary files a step recorded:
  none, because no step ran.

A fault in a top-level declaration is a runtime error rather than a
syntax error: ``bash -n`` reports nothing and the script aborts under
``set -e`` before it reaches its first prerequisite check. A name
declared ``readonly`` twice is that fault, and the second check is the
one that observes it.

A static check accompanies them, asserting no name is declared
``readonly`` more than once, so the failure is reported as the duplicate
name rather than as a bare non-zero exit.

Both bash checks are skipped, with the reason reported, on a host
carrying no ``bash``.
"""

import os
import re
import shutil
import subprocess

import pytest
from conftest import REPO_ROOT

#: Bootstrap script under test.
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup_dev_environment.sh"

#: Statement that calls the script's entry point. It is removed for the
#: execution check, and its presence is asserted, so a change to the
#: shape of the entry point fails here rather than silently turning the
#: check into a no-op.
ENTRY_POINT = 'main "$@"'

#: Shape of one ``readonly`` declaration, capturing the name declared.
READONLY_DECLARATION = re.compile(
    r"^\s*readonly\s+([A-Za-z_][A-Za-z0-9_]*)\s*=", re.MULTILINE
)

#: Shape of one function definition at the top level.
FUNCTION_DEFINITION = re.compile(
    r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{", re.MULTILINE
)

#: Seconds either bash check is allowed to take.
CHECK_TIMEOUT = 60

#: Message reported when the host carries no bash.
NO_BASH = "no bash interpreter is available on this host"


def _script_text():
    """Returns the script exactly as it is committed."""
    return SETUP_SCRIPT.read_text(encoding="utf-8")


def _bash():
    """Returns the bash interpreter to use, or ``None``."""
    found = shutil.which("bash")
    if found:
        return found
    for candidate in (
        r"C:\Program Files\Git\bin\bash.exe",
        "/bin/bash",
        "/usr/bin/bash",
    ):
        if os.path.isfile(candidate):
            return candidate
    return None


def _run(interpreter, *arguments):
    """Runs bash with ``arguments`` and returns the completed process."""
    return subprocess.run(
        [interpreter] + list(arguments),
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=CHECK_TIMEOUT,
    )


def _decoded(stream):
    """Returns one captured stream as text."""
    return stream.decode("utf-8", "replace")


def test_the_script_declares_no_name_readonly_more_than_once():
    """Asserts no name is frozen twice.

    A second ``readonly`` over a name already frozen fails at run time,
    which ends the script under ``set -e`` before any prerequisite is
    checked. The names are compared here so the failure is reported as
    the duplicate rather than as a bare non-zero exit.
    """
    declared = READONLY_DECLARATION.findall(_script_text())
    duplicated = sorted(
        set(name for name in declared if declared.count(name) > 1)
    )

    assert declared
    assert duplicated == [], duplicated


def test_the_script_calls_its_entry_point_exactly_once():
    """Asserts the entry point is the single statement removed below."""
    text = _script_text()

    assert text.count(ENTRY_POINT) == 1
    assert text.rstrip().endswith(ENTRY_POINT)


def test_the_script_parses():
    """Asserts ``bash -n`` reports no syntax error."""
    interpreter = _bash()
    if interpreter is None:
        pytest.skip(NO_BASH)

    completed = _run(interpreter, "-n", str(SETUP_SCRIPT))

    assert completed.returncode == 0, _decoded(completed.stderr)
    assert _decoded(completed.stderr) == ""


def test_every_top_level_statement_runs_without_mutating_anything(
    tmp_path,
):
    """Asserts the script starts.

    The committed script is run with its entry-point invocation removed,
    so every shell option, ``readonly`` declaration, variable assignment,
    trap and function definition is executed and no step is called. A
    top-level fault -- a name declared ``readonly`` twice among them --
    ends the run under ``set -e``, which this asserts it does not.

    The temporary directory is asserted to hold nothing but the copy
    afterwards, which holds because no step ran: the script creates
    nothing until ``main`` calls one.
    """
    interpreter = _bash()
    if interpreter is None:
        pytest.skip(NO_BASH)

    text = _script_text()
    assert text.count(ENTRY_POINT) == 1
    prologue = tmp_path / "setup_prologue.sh"
    prologue.write_text(text.replace(ENTRY_POINT, ""), encoding="utf-8")

    completed = _run(interpreter, str(prologue))

    assert completed.returncode == 0, _decoded(completed.stderr)
    assert "readonly variable" not in _decoded(completed.stderr)
    assert "Setup failed at line" not in _decoded(completed.stderr)
    assert _decoded(completed.stderr) == ""
    assert sorted(entry.name for entry in tmp_path.iterdir()) == [
        prologue.name
    ]


def test_the_prologue_check_would_report_a_duplicate_declaration(
    tmp_path,
):
    """Asserts the check above detects the fault it exists for.

    A second ``readonly`` over a name the script already freezes is
    written into a copy, and the copy is required to exit non-zero and to
    report ``readonly variable``.
    """
    interpreter = _bash()
    if interpreter is None:
        pytest.skip(NO_BASH)

    text = _script_text()
    declared = READONLY_DECLARATION.findall(text)
    assert declared
    repeated = 'readonly {0}="repeated"\n'.format(declared[0])
    faulty = tmp_path / "setup_with_a_duplicate.sh"
    faulty.write_text(
        text.replace(ENTRY_POINT, "").replace(
            "\n# Interpreter found by check_software",
            "\n" + repeated + "\n# Interpreter found by check_software",
            1,
        ),
        encoding="utf-8",
    )

    completed = _run(interpreter, str(faulty))

    assert completed.returncode != 0
    assert "readonly variable" in _decoded(completed.stderr)


def test_the_script_defines_every_step_its_entry_point_calls():
    """Asserts the entry point calls only functions the script defines.

    A step named in ``main`` that no definition provides would fail only
    once that step was reached, which is after the script has begun
    changing the environment.
    """
    text = _script_text()
    defined = set(FUNCTION_DEFINITION.findall(text))
    body = re.search(
        r"^main\(\)\s*\{(?P<body>.*?)^\}", text, re.MULTILINE | re.DOTALL
    )

    assert body is not None
    called = [
        line.strip()
        for line in body.group("body").splitlines()
        if re.match(r"^\s*[a-z_][a-z0-9_]*\s*$", line)
    ]
    assert called
    for step in called:
        assert step in defined, step
