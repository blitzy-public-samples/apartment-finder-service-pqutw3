"""Every line reference the review documents cite is read back and checked.

A reviewer follows a citation to a line and reads what is there. A
citation that has drifted sends that reviewer to the wrong line, and the
review document is the one artefact whose whole purpose is to direct
attention, so a stale reference in it is worse than no reference. The
citations were wrong once already: the five Python-pin references named
lines 10, 2, 19, 99 and 24, which described an earlier working tree.

The cases below take the four pin sites this repository configures plus
the one it carries in code, resolve each cited line in the file it names,
and assert the line still contains the construct the document says it
does. They also assert the review document still cites those exact lines,
so a correction to one side without the other fails here.

Nothing in this module reads a line number from a variable the document
supplies at run time: the expected pairs are written out below, so the
document and the code have to be brought into agreement deliberately.
"""

import re

import pytest

from backend.tests import support

#: Repository root, resolved from this module's location.
REPOSITORY_ROOT = support.REPO_ROOT

#: The review document whose citations are checked.
REVIEW_DOCUMENT = "docs/review/CRITICAL_DECISIONS.md"

#: Every runtime pin site, as (path, line number, required substring).
#:
#: The AAP holds the interpreter at 3.9 and names these five places. Four
#: are configuration and the fifth is code: the decorator at the first
#: entry was removed in Python 3.11, which is what makes the pin a
#: property of the codebase rather than of its deployment.
PIN_SITES = (
    (
        "backend/app/tasks/listing_updater.py",
        370,
        "@asyncio.coroutine",
    ),
    ("infrastructure/docker/Dockerfile.backend", 1, "python:3.9-slim"),
    (".github/workflows/ci.yml", 88, "3.9"),
    ("infrastructure/terraform/main.tf", 386, "python39"),
    ("scripts/deploy.sh", 669, "python39"),
)

#: Line references the review document must no longer carry for the pin
#: sites, each having described an earlier tree.
WITHDRAWN_CITATIONS = (
    "backend/app/tasks/listing_updater.py:10",
    "infrastructure/docker/Dockerfile.backend:2",
    ".github/workflows/ci.yml:19",
    "infrastructure/terraform/main.tf:99",
    "scripts/deploy.sh:24",
)


def _lines(relative_path):
    """Returns the lines of ``relative_path`` under the repository root."""
    target = REPOSITORY_ROOT / relative_path
    assert target.is_file(), relative_path
    return target.read_text(encoding="utf-8").splitlines()


def _document_text():
    """Returns the review document as one string."""
    return (REPOSITORY_ROOT / REVIEW_DOCUMENT).read_text(encoding="utf-8")


@pytest.mark.parametrize("path,number,required", PIN_SITES)
def test_the_cited_line_carries_what_the_document_says(
    path, number, required
):
    """The cited line exists and contains the named construct."""
    lines = _lines(path)

    assert number <= len(lines), (path, number, len(lines))
    assert required in lines[number - 1], (path, number, lines[number - 1])


@pytest.mark.parametrize("path,number,required", PIN_SITES)
def test_the_review_document_cites_that_line(path, number, required):
    """The document names the line this module asserts against."""
    assert "%s:%d" % (path, number) in _document_text(), (path, number)


@pytest.mark.parametrize("withdrawn", WITHDRAWN_CITATIONS)
def test_no_withdrawn_citation_survives_in_the_document(withdrawn):
    """A corrected reference is not still present as a live citation.

    The withdrawn references are quoted once, in the sentence recording
    that they were corrected. That sentence names them as bare numbers
    rather than as `path:line` citations, so this check distinguishes the
    record of the correction from a citation a reviewer would follow.
    """
    assert withdrawn not in _document_text(), withdrawn


@pytest.mark.parametrize("path,number,required", PIN_SITES)
def test_the_construct_appears_only_where_it_is_cited(
    path, number, required
):
    """Every line carrying the pin in that file names the same pin.

    A citation is only useful if it points at a line that agrees with
    every other line declaring the same thing. Two files declare the pin
    more than once for reasons that are correct -- the workflow sets up the
    interpreter in each of its jobs, and the release script declares the
    function runtime as a constant and then passes it as a flag -- so what
    is asserted is that the cited line carries the construct and that no
    other line carrying it disagrees with it.
    """
    carrying = [
        index
        for index, line in enumerate(_lines(path), start=1)
        if required in line and not line.strip().startswith("#")
    ]

    assert number in carrying, (path, number, carrying)
    for index in carrying:
        assert required in _lines(path)[index - 1], (path, index)


def test_every_pin_site_the_document_claims_is_covered_here():
    """The document claims five sites, and five are asserted.

    A sixth site added to the document without a case here would go
    unchecked, so the count the document states is read back from it.
    """
    text = _document_text()

    assert "load-bearing in five independent places" in text
    assert len(PIN_SITES) == 5


def test_the_document_names_this_module_as_the_check():
    """The document points a reviewer at this module by name.

    The reviewer instruction says to confirm the check exists rather than
    to count lines by hand, so the pointer has to resolve.
    """
    text = _document_text()
    module = "backend/tests/security/test_documentation_citations.py"

    assert module in text
    assert (REPOSITORY_ROOT / module).is_file()


@pytest.mark.parametrize(
    "path",
    [
        "docs/security/DECISION_LOG.md",
        "docs/security/TRACEABILITY_MATRIX.md",
        "docs/security/RESIDUAL_RISK.md",
        "docs/security/CREDENTIAL_ROTATION.md",
        REVIEW_DOCUMENT,
        "blitzy-deck/executive-summary.html",
        "SECURITY.md",
        "README.md",
    ],
)
def test_every_document_the_others_reference_is_present(path):
    """Each document the set cross-references exists.

    The decision log carried five rows in successive rounds recording
    four of these as absent. They are present now, and this case is what
    keeps that reconciliation honest.
    """
    assert (REPOSITORY_ROOT / path).is_file(), path


def test_no_document_claims_the_credential_rotation_is_complete():
    """Rotation is an operator action and no document may claim it done.

    The exposed values remain reachable in the repository's history, so a
    document asserting the rotation has happened would report a risk as
    closed while a live credential is still readable from any clone.
    """
    claims = re.compile(
        r"(credentials?|secrets?|keys?)\s+(have|has|were|was)\s+"
        r"(been\s+)?(rotated|revoked)",
        re.IGNORECASE,
    )
    for path in (
        "docs/security/CREDENTIAL_ROTATION.md",
        "docs/security/RESIDUAL_RISK.md",
        REVIEW_DOCUMENT,
        "SECURITY.md",
        "README.md",
    ):
        text = (REPOSITORY_ROOT / path).read_text(encoding="utf-8")
        for match in claims.finditer(text):
            window = text[max(0, match.start() - 200):match.end() + 200]
            assert any(
                qualifier in window.lower()
                for qualifier in (
                    "must",
                    "has not",
                    "have not",
                    "not yet",
                    "outstanding",
                    "until",
                    "once",
                    "after",
                    "treat",
                    "assume",
                    "should",
                    "cannot",
                    "no document",
                    "would",
                )
            ), (path, match.group(0))


#: Documents whose test citations must resolve.
CITING_DOCUMENTS = (
    "docs/security/DECISION_LOG.md",
    "docs/security/TRACEABILITY_MATRIX.md",
    "docs/security/RESIDUAL_RISK.md",
    "docs/security/CREDENTIAL_ROTATION.md",
    REVIEW_DOCUMENT,
    "SECURITY.md",
    "README.md",
)

#: Cues that introduce the abandoned side of a rename.
#:
#: A rename is recorded by naming both sides of it, so the abandoned name
#: has to stay readable and is not required to resolve. The name it was
#: changed *to* is a live citation and must resolve, so the cue alone is
#: not enough to exempt a name: it also has to sit on the left of the
#: "to" that names the replacement. Matching the cue anywhere nearby
#: would exempt both sides at once and wave through exactly the two
#: broken rename targets this case was written to catch.
RENAME_CUES = (
    "rename",
    "old name",
    "was called",
    "formerly",
    "previously named",
)

#: How far back a rename cue may sit from the name it introduces.
RENAME_CUE_REACH = 80

#: How far after a name the "to" naming its replacement may sit.
RENAME_TARGET_REACH = 24


def _defined_test_names():
    """Returns every test function and test module name in the suite."""
    functions = set()
    modules = set()
    for path in sorted((REPOSITORY_ROOT / "backend" / "tests").rglob("*.py")):
        modules.add(path.stem)
        text = path.read_text(encoding="utf-8")
        functions.update(re.findall(r"def (test_\w+)", text))
    return functions, modules


@pytest.mark.parametrize("path", CITING_DOCUMENTS)
def test_every_test_the_documents_name_resolves(path):
    """A test named by a document is a function, a module or a prefix.

    A citation exists to be followed. Four in this set named cases the
    suite does not define: two rename targets a later round refined, one
    case renamed when its value became required, and one document-presence
    case named from memory rather than read back. Each sent a reviewer
    looking for a test that was not there, which is the same defect as a
    stale line number and is caught the same way.

    A name is accepted when the suite defines it as a function, when it is
    a module basename, when it is the prefix of at least one defined
    function so that ``test_h2_*`` resolves, or when it is the abandoned
    side of a rename the text records.
    """
    functions, modules = _defined_test_names()
    text = (REPOSITORY_ROOT / path).read_text(encoding="utf-8")

    unresolved = []
    for match in re.finditer(r"\btest_[a-z0-9_]+", text):
        name = match.group(0)
        if name in functions or name in modules:
            continue
        if any(candidate.startswith(name) for candidate in functions):
            continue
        before = text[max(0, match.start() - RENAME_CUE_REACH):match.start()]
        after = text[match.end():match.end() + RENAME_TARGET_REACH]
        introduced = any(cue in before.lower() for cue in RENAME_CUES)
        replaced_by = "to `" in after
        if introduced and replaced_by:
            continue
        unresolved.append((name, text[:match.start()].count("\n") + 1))

    assert not unresolved, "{}: unresolved test citations {}".format(
        path, unresolved
    )


#: The open items this remediation deliberately left open.
#:
#: Each is recorded so a reader of either document learns what was not
#: delivered. An item that quietly leaves both registers stops being a
#: disclosure and becomes an omission, which is the failure this guards.
OPEN_ITEMS = (
    "O-1",
    "O-2",
    "O-3",
    "O-4",
    "O-5",
    "O-6",
    "O-7",
    "O-8",
)

#: Documents that must carry every open item.
OPEN_ITEM_REGISTERS = (
    "docs/security/RESIDUAL_RISK.md",
    REVIEW_DOCUMENT,
)


@pytest.mark.parametrize("path", OPEN_ITEM_REGISTERS)
@pytest.mark.parametrize("item", OPEN_ITEMS)
def test_every_open_item_is_registered(item, path):
    """Both registers name every deliberately open item.

    The reviewer signing off the five decisions would otherwise be
    entitled to read anything not named as a risk as delivered and
    working. Four of these eight are functional gaps rather than security
    weaknesses, which is exactly the kind of shortfall a security document
    tends to omit.
    """
    text = (REPOSITORY_ROOT / path).read_text(encoding="utf-8")
    assert "| {} |".format(item) in text, (path, item)


@pytest.mark.parametrize("path", OPEN_ITEM_REGISTERS)
def test_every_open_item_carries_a_governing_clause(path):
    """No open item is deferred without the clause that permits it.

    A deferral with no authority behind it is indistinguishable from work
    that was simply not done, so each row has to cite the section of the
    Agent Action Plan it rests on.
    """
    text = (REPOSITORY_ROOT / path).read_text(encoding="utf-8")
    for item in OPEN_ITEMS:
        prefix = "| {} |".format(item)
        row = next(
            line for line in text.splitlines() if line.startswith(prefix)
        )
        assert re.search(r"AAP\s+§0\.\d", row), (path, item, row[:120])


def test_the_open_items_are_excluded_from_the_advisory_count():
    """The advisory arithmetic is untouched by the open-item register.

    Every headline figure in the residual-risk register is reproducible
    from one ``pip-audit`` invocation. Folding non-advisory items into
    those counts would make them unreproducible, so the register has to
    keep saying that it does not.
    """
    text = (REPOSITORY_ROOT / "docs/security/RESIDUAL_RISK.md").read_text(
        encoding="utf-8"
    )

    assert "Open items that are not dependency advisories" in text
    assert "none enters any count above" in text
    assert "seven" in text.lower()


#: The workflow the disclosure policy documents its gates from.
INTEGRATION_WORKFLOW = ".github/workflows/ci.yml"

#: The document that reproduces those gates for a reporter.
DISCLOSURE_POLICY = "SECURITY.md"

#: Gate commands the policy must reproduce as the workflow invokes them.
#:
#: An earlier revision paraphrased these: it dropped ``--strict``, dropped
#: every suppression identifier, and ran the audit from the repository
#: root. Each difference changes the result, so a reporter following the
#: policy did not reproduce the gate they believed they were reproducing.
DOCUMENTED_GATE_COMMANDS = (
    "flake8 .",
    "pip-audit --strict -r backend/requirements.txt",
    "pip-audit --strict -r backend/requirements-dev.txt",
    "bandit -r backend/app -ll",
    "! pip show python-multipart",
    "python -m pytest backend/tests --cov=backend/app "
    "--cov-report=xml:backend/coverage.xml",
    "python -m pytest backend/tests/security -q",
)


@pytest.mark.parametrize("command", DOCUMENTED_GATE_COMMANDS)
def test_the_policy_documents_the_gate_the_workflow_runs(command):
    """Every documented gate command is one the workflow actually runs."""
    workflow = (REPOSITORY_ROOT / INTEGRATION_WORKFLOW).read_text(
        encoding="utf-8"
    )
    policy = (REPOSITORY_ROOT / DISCLOSURE_POLICY).read_text(encoding="utf-8")

    assert command in policy, (DISCLOSURE_POLICY, command)

    if command in workflow:
        return

    #: The workflow may split one documented invocation across steps and
    #: still run it -- the backend suite is run as the security cases and
    #: then the rest, with coverage appended across both, so the whole
    #: suite is measured in two steps rather than one. A documented command
    #: is then reproduced by the workflow when every element of it is
    #: invoked there, which is what a reporter following the policy needs.
    for element in command.split():
        assert element in workflow, (INTEGRATION_WORKFLOW, command, element)


def test_the_policy_suppresses_exactly_what_the_workflow_suppresses():
    """The suppression identifiers match the workflow's, in both manifests.

    Fourteen identifiers are suppressed across two manifests, and the two
    lists are different. A policy carrying a stale or partial list invites
    a reporter to run an audit that reports findings the gate suppresses,
    or to suppress findings the gate reports.
    """
    workflow = (REPOSITORY_ROOT / INTEGRATION_WORKFLOW).read_text(
        encoding="utf-8"
    )
    policy = (REPOSITORY_ROOT / DISCLOSURE_POLICY).read_text(encoding="utf-8")

    pattern = re.compile(r"--ignore-vuln (PYSEC-[\d-]+)")
    in_workflow = pattern.findall(workflow)
    in_policy = pattern.findall(policy)

    assert len(in_workflow) == 14, in_workflow
    assert in_policy == in_workflow


def test_the_policy_publishes_no_unresolvable_contact():
    """No document offers a fabricated address as a reporting channel.

    A channel that reaches nobody is worse than an absent one: a reporter
    who uses it has done everything asked and the report is lost silently.
    """
    for path in (DISCLOSURE_POLICY, "README.md"):
        text = (REPOSITORY_ROOT / path).read_text(encoding="utf-8")
        for placeholder in ("your.email@example.com", "your-username"):
            start = 0
            while True:
                at = text.find(placeholder, start)
                if at == -1:
                    break
                start = at + len(placeholder)
                # Naming it to record its removal is permitted; offering it
                # as a live channel is not.
                window = text[max(0, at - 300):at + 300].lower()
                assert any(
                    marker in window
                    for marker in (
                        "earlier revision",
                        "earlier revisions",
                        "removed rather than",
                        "is gone rather than",
                        "no maintainer",
                    )
                ), (path, placeholder, window[:140])
