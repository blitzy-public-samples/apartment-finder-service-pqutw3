"""Semantic guards over the accepted residual dependency advisories.

Seven advisories are accepted in `docs/security/RESIDUAL_RISK.md` because
no fix for them installs under the pinned interpreter. Each acceptance
rests on the defect being unreachable from this service, so this module
asserts that unreachability rather than restating it.

The continuous-integration workflow carries a textual pre-filter over the
same constructs. A literal search cannot see an import alias, an
attribute reached through a module object, or a parameter whose type makes
a plain attribute access the guarded one, so the assertions here read the
abstract syntax tree of every module under ``backend/app`` instead. What
is asserted:

* no guarded module is imported, under its own name or an alias, and none
  is reached through a dynamic import naming it as a string
* no guarded symbol is imported from anywhere, under its own name or an
  alias, and none is reached as an attribute of an imported module
* no request object has its reconstructed address or its form payload
  read, whether the object arrives as a parameter annotated with the
  framework request type, under one of the conventional parameter names,
  or through an alias of that type
* the package deliberately omitted from both manifests stays omitted
* every advisory the audit gates suppress is registered in the residual
  register, so a suppression cannot outlive its record
* the textual pre-filter covers the patterns the register says it covers,
  and covers no control

``backend/app`` is the scope, because it is the code an HTTP request
reaches: nothing under ``backend/tests`` is installed into the runtime
image, and ``backend/requirements.txt`` is what that image installs. The
register is the authority for which advisories are accepted, and the two
manifests are the authority for what is installed.
"""

import ast
import re

import pytest
from conftest import REPO_ROOT

#: Application package, the scope of every reachability assertion below.
APPLICATION_DIR = REPO_ROOT / "backend" / "app"

#: Runtime dependency manifest.
RUNTIME_MANIFEST = REPO_ROOT / "backend" / "requirements.txt"

#: Development dependency manifest.
DEVELOPMENT_MANIFEST = REPO_ROOT / "backend" / "requirements-dev.txt"

#: Register recording every accepted advisory.
RESIDUAL_REGISTER = REPO_ROOT / "docs" / "security" / "RESIDUAL_RISK.md"

#: Workflows carrying the audit gates.
WORKFLOWS = (
    REPO_ROOT / ".github" / "workflows" / "ci.yml",
    REPO_ROOT / ".github" / "workflows" / "cd.yml",
)

#: Modules whose import would make an accepted advisory reachable,
#: keyed by the advisory each one belongs to.
GUARDED_MODULES = {
    "click": "PYSEC-2026-2132",
    "multipart": "PYSEC-2026-249",
    "starlette.staticfiles": "PYSEC-2026-2281",
    "starlette.endpoints": "PYSEC-2026-2280",
}

#: Module the application imports for one symbol only. Every other symbol
#: it publishes belongs to PYSEC-2026-2280's dispatch surface.
NARROWED_MODULE = "starlette.routing"

#: The symbols the application may import from :data:`NARROWED_MODULE`.
NARROWED_MODULE_SYMBOLS = ("Match",)

#: Symbols whose use would make an accepted advisory reachable, keyed by
#: the advisory each one belongs to.
GUARDED_SYMBOLS = {
    "StaticFiles": "PYSEC-2026-2281",
    "HTTPEndpoint": "PYSEC-2026-2280",
    "Route": "PYSEC-2026-2280",
    "WebSocketRoute": "PYSEC-2026-2280",
    "UploadFile": "PYSEC-2026-249",
    "File": "PYSEC-2026-249",
    "Form": "PYSEC-2026-249",
    "OAuth2PasswordRequestForm": "PYSEC-2026-249",
    "set_key": "PYSEC-2026-2270",
    "unset_key": "PYSEC-2026-2270",
}

#: Attributes of a request object whose read would make an accepted
#: advisory reachable, keyed by the advisory each one belongs to.
GUARDED_REQUEST_ATTRIBUTES = {
    "url": "PYSEC-2026-161",
    "base_url": "PYSEC-2026-248",
    "form": "PYSEC-2026-249",
}

#: Type whose annotation marks a parameter as a request object.
REQUEST_TYPE = "Request"

#: Parameter names treated as request objects without an annotation.
REQUEST_PARAMETER_NAMES = ("request", "req")

#: Package omitted from both manifests.
OMITTED_PACKAGE = "python-multipart"

#: Patterns the textual pre-filter in the workflow covers.
PRE_FILTER_PATTERNS = (
    r"request\.form",
    r"request\.url",
    "StaticFiles",
    "HTTPEndpoint",
    r"Route\(",
    "set_key",
    "unset_key",
    r"\bclick\b",
)

#: Control the pre-filter must not treat as a risk.
PRE_FILTER_EXCLUSION = "TrustedHost"

#: Backend tree, the wider of the two scopes the register reports.
BACKEND_DIR = REPO_ROOT / "backend"

#: The fourteen patterns the register's broad reachability measurement
#: searches, in the order it lists them. Matched case-sensitively and
#: literally, which is how the register describes the search.
REACHABILITY_PATTERNS = (
    "request.form",
    "UploadFile",
    "File(",
    "Form(",
    "OAuth2PasswordRequestForm",
    "multipart",
    "StaticFiles",
    "HTTPEndpoint",
    "Route(",
    "request.url",
    "click",
    "set_key",
    "unset_key",
    "TrustedHost",
)

#: Patterns that return no match anywhere under ``backend/app``. Every
#: pattern but the control does, which is the thirteen the register
#: publishes for that scope.
REACHABILITY_ZERO_IN_APPLICATION = tuple(
    pattern
    for pattern in REACHABILITY_PATTERNS
    if pattern != PRE_FILTER_EXCLUSION
)

#: The two directories a reachability match may sit in. The application
#: package is the scope that bears on reachability; the test tree names the
#: constructs in order to assert their absence and is installed into no
#: image. A match anywhere else would be production code.
REACHABILITY_PERMITTED_ROOTS = ("backend/app", "backend/tests")


def _application_modules():
    """Returns every module under the application package."""
    return sorted(APPLICATION_DIR.rglob("*.py"))


def _tree(path):
    """Returns the parsed syntax tree of one module."""
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_modules(tree):
    """Returns every module name one tree imports.

    Covers ``import a.b``, ``import a.b as c``, ``from a.b import c`` and
    a dynamic import whose module name is a string literal.
    """
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module)
        elif isinstance(node, ast.Call):
            target = node.func
            name = getattr(target, "attr", getattr(target, "id", ""))
            if name != "import_module" or not node.args:
                continue
            argument = node.args[0]
            if isinstance(argument, ast.Str):
                found.add(argument.s)
    return found


def _imported_symbols(tree):
    """Returns every symbol name one tree imports.

    The name recorded is the one the exporting module publishes, so an
    ``as`` alias does not hide it.
    """
    return set(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    )


def _attribute_names(tree):
    """Returns every attribute name one tree reads or writes."""
    return set(
        node.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
    )


def _annotation_names(annotation):
    """Returns the identifiers appearing in one annotation."""
    if annotation is None:
        return set()
    return set(
        node.id
        for node in ast.walk(annotation)
        if isinstance(node, ast.Name)
    ) | set(
        node.attr
        for node in ast.walk(annotation)
        if isinstance(node, ast.Attribute)
    )


def _request_aliases(tree):
    """Returns the local names an alias of the request type carries."""
    aliases = {REQUEST_TYPE}
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        for alias in node.names:
            if alias.name == REQUEST_TYPE and alias.asname:
                aliases.add(alias.asname)
    return aliases


def _request_bound_names(tree):
    """Returns the local names that hold a request object.

    A name qualifies when its parameter annotation names the request type
    or an alias of it, or when the parameter is conventionally named for a
    request. Assignments from such a name are followed one step, so
    ``held = request`` is covered too.
    """
    aliases = _request_aliases(tree)
    bound = set(REQUEST_PARAMETER_NAMES)

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        arguments = node.args
        every = (
            list(arguments.args)
            + list(arguments.posonlyargs)
            + list(arguments.kwonlyargs)
        )
        for argument in every:
            if _annotation_names(argument.annotation) & aliases:
                bound.add(argument.arg)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Name):
            continue
        if node.value.id not in bound:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                bound.add(target.id)
    return bound


def _request_attribute_reads(tree):
    """Returns the guarded attributes read from a request object."""
    bound = _request_bound_names(tree)
    found = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Attribute):
            continue
        if node.attr not in GUARDED_REQUEST_ATTRIBUTES:
            continue
        receiver = node.value
        if isinstance(receiver, ast.Name) and receiver.id in bound:
            found.add(node.attr)
        elif isinstance(receiver, ast.Attribute) and (
            receiver.attr in bound
        ):
            found.add(node.attr)
    return found


def _manifest_names(path):
    """Returns the distribution names one manifest pins."""
    return set(
        match.group(1).lower()
        for match in re.finditer(
            r"^([A-Za-z0-9._-]+)(?:\[[^\]]*\])?==",
            path.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )


def _suppressed_advisories():
    """Returns every advisory identifier the audit gates suppress."""
    found = set()
    for path in WORKFLOWS:
        found.update(
            re.findall(
                r"--ignore-vuln\s+(\S+)",
                path.read_text(encoding="utf-8"),
            )
        )
    return found


def test_the_application_package_carries_modules_to_check():
    """Asserts the scope of the assertions below is not empty."""
    modules = _application_modules()

    assert len(modules) >= 20
    for path in modules:
        assert path.is_file(), path


@pytest.mark.parametrize(
    "module,advisory", sorted(GUARDED_MODULES.items())
)
def test_no_guarded_module_is_imported(module, advisory):
    """Asserts no module behind an accepted advisory is imported."""
    offenders = []
    for path in _application_modules():
        imported = _imported_modules(_tree(path))
        for name in imported:
            if name == module or name.startswith(module + "."):
                offenders.append((path.name, name))
    assert offenders == [], (advisory, offenders)


@pytest.mark.parametrize(
    "symbol,advisory", sorted(GUARDED_SYMBOLS.items())
)
def test_no_guarded_symbol_is_imported_or_reached(symbol, advisory):
    """Asserts no symbol behind an accepted advisory is used."""
    offenders = []
    for path in _application_modules():
        tree = _tree(path)
        if symbol in _imported_symbols(tree):
            offenders.append((path.name, "import"))
        if symbol in _attribute_names(tree):
            offenders.append((path.name, "attribute"))
    assert offenders == [], (advisory, offenders)


@pytest.mark.parametrize(
    "attribute,advisory", sorted(GUARDED_REQUEST_ATTRIBUTES.items())
)
def test_no_request_attribute_behind_an_advisory_is_read(
    attribute, advisory
):
    """Asserts the reconstructed address and the form are never read."""
    offenders = []
    for path in _application_modules():
        if attribute in _request_attribute_reads(_tree(path)):
            offenders.append(path.name)
    assert offenders == [], (advisory, offenders)


def test_the_narrowed_module_supplies_only_its_permitted_symbol():
    """Asserts the routing module is imported for one symbol only.

    Every other symbol that module publishes belongs to the dispatch
    surface PYSEC-2026-2280 concerns, so an added import is a change to
    review rather than to absorb.
    """
    imported = set()
    for path in _application_modules():
        for node in ast.walk(_tree(path)):
            if not isinstance(node, ast.ImportFrom):
                continue
            if node.module != NARROWED_MODULE:
                continue
            imported.update(alias.name for alias in node.names)

    assert imported.issubset(set(NARROWED_MODULE_SYMBOLS)), imported


def test_the_request_detection_recognises_an_annotated_alias():
    """Asserts an aliased request type is still detected.

    The guard is only stronger than a literal search if it follows the
    alias, so the detection is exercised against a module that uses one.
    """
    source = (
        "from starlette.requests import Request as Inbound\n"
        "\n"
        "\n"
        "def read(inbound: Inbound):\n"
        "    return inbound.url\n"
    )
    tree = ast.parse(source)

    assert "Inbound" in _request_aliases(tree)
    assert "inbound" in _request_bound_names(tree)
    assert _request_attribute_reads(tree) == {"url"}


def test_the_request_detection_recognises_a_reassigned_name():
    """Asserts a request held under another name is still detected."""
    source = (
        "from fastapi import Request\n"
        "\n"
        "\n"
        "def read(incoming: Request):\n"
        "    held = incoming\n"
        "    return held.form\n"
    )
    tree = ast.parse(source)

    assert _request_attribute_reads(tree) == {"form"}


def test_the_module_detection_recognises_an_aliased_import():
    """Asserts an aliased module import is still detected."""
    tree = ast.parse("import click as cli\n")

    assert "click" in _imported_modules(tree)


def test_the_module_detection_recognises_a_dynamic_import():
    """Asserts a dynamically named module import is still detected."""
    tree = ast.parse(
        "from importlib import import_module\n"
        "loaded = import_module('click')\n"
    )

    assert "click" in _imported_modules(tree)


def test_the_symbol_detection_recognises_an_aliased_symbol():
    """Asserts an aliased symbol import is still detected."""
    tree = ast.parse(
        "from starlette.staticfiles import StaticFiles as Assets\n"
    )

    assert "StaticFiles" in _imported_symbols(tree)


def test_the_omitted_package_is_absent_from_both_manifests():
    """Asserts the package left out stays left out."""
    for path in (RUNTIME_MANIFEST, DEVELOPMENT_MANIFEST):
        assert OMITTED_PACKAGE not in _manifest_names(path), path.name


def test_every_suppressed_advisory_is_registered():
    """Asserts no audit suppression outlives its record."""
    register = RESIDUAL_REGISTER.read_text(encoding="utf-8")
    suppressed = _suppressed_advisories()

    assert len(suppressed) == 8
    for identifier in sorted(suppressed):
        assert identifier in register, identifier


def test_only_the_pipeline_carries_an_audit_gate():
    """Asserts one workflow owns the audit and the other requires it."""
    pipeline, deployment = (
        path.read_text(encoding="utf-8") for path in WORKFLOWS
    )

    assert "pip-audit" in pipeline
    assert "pip-audit" not in deployment
    assert "uses: ./.github/workflows/ci.yml" in deployment


def test_the_textual_pre_filter_covers_what_the_register_claims():
    """Asserts the workflow pattern list matches the register."""
    workflow = WORKFLOWS[0].read_text(encoding="utf-8")
    guard = workflow[workflow.index("Check residual advisory"):]
    guard = guard[:guard.index("- name: Run backend unit tests")]

    for pattern in PRE_FILTER_PATTERNS:
        assert pattern in guard, pattern
    assert PRE_FILTER_EXCLUSION not in guard
    assert "--include=*.py backend/app/" in guard


def test_the_register_records_the_semantic_guard():
    """Asserts the register points at the assertions in this module."""
    register = RESIDUAL_REGISTER.read_text(encoding="utf-8")

    assert "test_residual_risk_guards.py" in register
    assert "abstract syntax tree" in register
    assert "Development-only accepted advisories" in register


def _matching_files(root):
    """Returns each reachability pattern's matching files under ``root``.

    Searched the way the register describes it: case-sensitively and
    literally, over every ``.py`` file, with each path recorded relative to
    the repository root and with forward slashes so a result reads the same
    on either platform.
    """
    found = dict((pattern, set()) for pattern in REACHABILITY_PATTERNS)
    for path in sorted(root.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(REPO_ROOT).as_posix()
        for pattern in REACHABILITY_PATTERNS:
            if pattern in text:
                found[pattern].add(relative)
    return found


def test_thirteen_reachability_patterns_are_absent_from_the_application():
    """Asserts the register's published figure against the tree.

    The register reported thirteen of the fourteen patterns at zero while
    declaring the scope ``backend/``, where it is not true. The conclusion
    survived and the evidence as written did not, and nothing compared it to
    the tree. This case is that comparison at the scope the figure holds
    for, so the published figure cannot drift from what a reader measures.
    """
    matching = _matching_files(APPLICATION_DIR)
    absent = tuple(
        pattern for pattern in REACHABILITY_PATTERNS if not matching[pattern]
    )

    assert absent == REACHABILITY_ZERO_IN_APPLICATION, matching
    assert len(absent) == 13, absent
    assert matching[PRE_FILTER_EXCLUSION], PRE_FILTER_EXCLUSION


def test_no_reachability_match_sits_outside_the_two_permitted_roots():
    """Asserts the property the wider scope is reported for.

    No count is published at ``backend/`` and none can be: this module
    names all fourteen patterns as literals, so any tally over the tree that
    contains it is changed by asserting it. The stable property is where the
    matches sit rather than how many there are -- the application package,
    whose thirteen zeroes the case above asserts, and the test tree, which
    names the constructs in order to assert their absence and is installed
    into no image.
    """
    stray = sorted(
        (pattern, path)
        for pattern, paths in _matching_files(BACKEND_DIR).items()
        for path in paths
        if not path.startswith(REACHABILITY_PERMITTED_ROOTS)
    )

    assert stray == [], stray


def test_the_register_names_the_scope_each_reachability_result_holds_for():
    """Asserts each statement is published with its scope.

    A result published without its scope is the defect: read against the
    wider scope it is wrong, and read against the narrower one a reader
    cannot tell which was meant.
    """
    flowed = " ".join(RESIDUAL_REGISTER.read_text(encoding="utf-8").split())

    assert (
        "At `backend/app/`, thirteen of the fourteen return zero" in flowed
    )
    assert (
        "At `backend/`, most of the fourteen match, and no count is "
        "published for that scope" in flowed
    )
    assert (
        "no match anywhere under `backend/` sits outside `backend/app/` and "
        "`backend/tests/`" in flowed
    )
    assert "test_residual_risk_guards.py" in flowed
