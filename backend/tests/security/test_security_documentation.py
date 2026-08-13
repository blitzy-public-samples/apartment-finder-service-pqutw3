"""Consistency checks over the security documentation set.

Six documents describe this remediation to a reader who does not have the
code in front of them: the decision log, the traceability matrix, the
residual-risk register, the credential-rotation runbook, the critical
decision review and the published security policy, with the project
readme as the entry point. They are only useful while they agree with each
other and with the tree, so this module asserts the properties that a
later edit is most likely to break. What is asserted:

* every document exists, is non-empty, and links only to paths that exist
* every section, row and fragment reference resolves, so no document
  points at a section or a row that is not there
* the credential inventory is the same in the runbook, the review
  artefact and the policy, and covers the credential whose exposure route
  was a log record rather than a committed file
* the rotation sequence is stated in the same order everywhere it appears
* the delivered-path reconciliation in the matrix agrees with the tree,
  reaches the same set from both directions, and is not contradicted by a
  stale artefact-absence claim anywhere in the set

The runbook is the authority for the credential inventory. Where a
statement belongs to one document, the others point at it rather than
restating it, so these assertions check agreement rather than duplication.
"""

import re
import unicodedata

import pytest
import yaml
from conftest import REPO_ROOT

#: Decision log, the authority for why.
DECISION_LOG = REPO_ROOT / "docs" / "security" / "DECISION_LOG.md"

#: Traceability matrix, the authority for what maps to what.
TRACEABILITY_MATRIX = (
    REPO_ROOT / "docs" / "security" / "TRACEABILITY_MATRIX.md"
)

#: Residual-risk register, the authority for accepted advisories.
RESIDUAL_REGISTER = REPO_ROOT / "docs" / "security" / "RESIDUAL_RISK.md"

#: Credential-rotation runbook, the authority for the credential set.
ROTATION_RUNBOOK = (
    REPO_ROOT / "docs" / "security" / "CREDENTIAL_ROTATION.md"
)

#: Critical decision review, the Rule 3 artefact.
CRITICAL_DECISIONS = (
    REPO_ROOT / "docs" / "review" / "CRITICAL_DECISIONS.md"
)

#: Published vulnerability disclosure policy.
SECURITY_POLICY = REPO_ROOT / "SECURITY.md"

#: Workflow whose jobs the documents describe.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Project readme.
README = REPO_ROOT / "README.md"

#: Every document the assertions below read.
DOCUMENTS = (
    DECISION_LOG,
    TRACEABILITY_MATRIX,
    RESIDUAL_REGISTER,
    ROTATION_RUNBOOK,
    CRITICAL_DECISIONS,
    SECURITY_POLICY,
    README,
)

#: Credentials the runbook takes operator action on.
CREDENTIAL_SUBJECTS = (
    "Database credentials",
    "Google Cloud service-account key",
    "JWT signing key",
    "Listing-provider (Zillow) API key",
    "PayPal webhook identifier",
    "Seeded administrator credential",
    "Shared rate-limit store address",
)

#: Documents that must name the credential exposed through a log record.
DOCUMENTS_NAMING_THE_PROVIDER_KEY = (
    ROTATION_RUNBOOK,
    CRITICAL_DECISIONS,
    SECURITY_POLICY,
)

#: Ordered rotation steps, as every document states them.
ROTATION_STEPS = ("Revoke", "Rotate", "Delete", "Review prior access")

#: Artefacts earlier rows of the log described as absent. Each exists.
DELIVERED_ARTEFACTS = (
    TRACEABILITY_MATRIX,
    RESIDUAL_REGISTER,
    ROTATION_RUNBOOK,
    CRITICAL_DECISIONS,
    SECURITY_POLICY,
    REPO_ROOT / "blitzy-deck" / "executive-summary.html",
)

#: Log rows that call one of the artefacts above absent.
SUPERSEDED_ABSENCE_ROWS = ("26.19", "29.11", "30.15", "32.12", "33.11")

#: Log row that withdraws every row above.
WITHDRAWAL_ROW = "35.1.1"

#: Log rows that decided the first repair for the pool-exhaustion
#: finding, which was delivered and then measured not to remove the
#: stall. Each stands as chronology and points at the withdrawal.
SUPERSEDED_REPAIR_ROWS = ("97.2.3", "97.2.4", "97.2.5")

#: Section holding that withdrawal, as a reader cites it and as its
#: heading reads.
REPAIR_WITHDRAWAL_SECTION = "97.4"

REPAIR_WITHDRAWAL_HEADING = "### %s " % REPAIR_WITHDRAWAL_SECTION

#: Figures from the load run that falsified the first repair. The
#: conclusion alone is not followable; these are what showed it.
FALSIFYING_FIGURES = (
    "10 703 ms",
    "4.7 req/s",
    "31 203 ms",
    "2.2 req/s",
)

#: Paths the plan's mapping marks CREATE or UPDATE.
PLANNED_CHANGED_PATHS = 59

#: Paths matrix section 6 reaches from the finding side, enumerated by its
#: sections 6.2 and 6.3. A subset of the beyond-plan population, not the
#: whole of it: the rounds after the one that wrote section 6 delivered
#: more, and those are reached forward by section 2.9 and backward by 4.3.
UNPLANNED_DELIVERED_PATHS = 27

#: Paths the rounds after that one delivered beyond the plan, carried by
#: the matrix's section 2.9 second table and its section 4.3.
LATER_ROUND_PATHS = 62

#: Of those, the ones later rounds withdrew: sixteen retired by the
#: manifest consolidation and one, the provider lock file, withdrawn with
#: the provider version constraint it locked. They were delivered and then
#: retired, so they are indexed with their withdrawal stated and are absent
#: from the tree the delivered total measures.
RETIRED_PATHS = 17

#: Delivered paths in the current tree, which is the figure the matrix
#: publishes as its one authoritative baseline. Measured by
#: ``git diff --name-status a26f7fb HEAD`` against a clean working tree.
DELIVERED_PATHS = (
    PLANNED_CHANGED_PATHS
    + UNPLANNED_DELIVERED_PATHS
    + LATER_ROUND_PATHS
    - RETIRED_PATHS
)

#: Section reference prefix belonging to the Agent Action Plan. The plan
#: is not one of these documents, so a reference to it resolves nowhere
#: here and is excluded rather than treated as dangling.
PLAN_SECTION_PREFIX = "0."

#: A numbered heading, which is what a section reference resolves against.
HEADING_NUMBER = re.compile(r"^#{2,4}\s+(\d+(?:\.\d+)*)[.)]?\s", re.MULTILINE)

#: A numbered table row, which is what a row reference resolves against.
ROW_NUMBER = re.compile(r"^\|\s*(\d+(?:\.\d+)+)\s*\|", re.MULTILINE)

#: A reference to a section or a row of one of these documents.
RECORD_REFERENCE = re.compile(
    r"(?:\u00a7|[Rr]ows?\s+|[Ss]ections?\s+)(\d+(?:\.\d+)*)"
)

#: Section numbers the decision log removed when it was consolidated onto
#: one decision set. They held a duplicate re-issue of sections 1 to 34,
#: with 44 added to every section prefix. The log publishes the rule for
#: resolving a citation in this band and row 91.5.1 records the removal.
REMOVED_SECTION_BAND = (45, 78)

#: Offset the published rule applies to a citation in that band.
REMOVED_SECTION_OFFSET = 44

#: A same-document fragment link, as a reader's browser resolves it.
FRAGMENT_LINK = re.compile(r"\]\(#([^)\s]+)\)")

#: An ATX heading, which is the only construct that offers an anchor.
_HEADING = re.compile(r"^#{1,6}[ \t]+(.+?)[ \t]*#*$")

#: A fence, opening or closing. Headings inside one are not headings: a
#: shell comment in an extracted command starts with the same character.
_FENCE = re.compile(r"^\s*```")

#: Placeholder contact values these documents once published. Each may
#: still be named in prose that disowns it, never offered as a contact.
WITHDRAWN_CONTACTS = ("your.email@example.com", "Your Name", "your-username")

#: Documents that publish a contact or a reporting channel.
CONTACT_DOCUMENTS = (SECURITY_POLICY, README)

#: Scope of Guard 2's textual layer, as the workflow runs it.
GUARD_TEXTUAL_SCOPE = "--include=*.py backend/app/"

#: The continuous-integration job that is expected to fail and gates
#: nothing, named exactly as the workflow names it.
TOLERATED_JOB = "Frontend checks (known blocker, gates nothing)"

#: Deployment inputs that are new or renamed by this work. A deployment
#: configured before it will not have them, so the readme has to say so.
#:
#: The three the Cloud Function step reads replace an earlier trio. The
#: function's name and entry point stopped being inputs when they became
#: constants in the script that match the Terraform configuration owning
#: the function, and ``CLOUD_FUNCTION_SOURCE_ARCHIVE`` was replaced by the
#: object name and its digest, because the object is named after the
#: archive's content digest and a single ``gs://`` string cannot be
#: compared against what the bucket actually holds.
DEPLOYMENT_INPUTS = (
    "GKE_CLUSTER_REGION",
    "GKE_DEPLOY_RUNNER",
    "GCP_WORKLOAD_IDENTITY_PROVIDER",
    "REACT_APP_API_BASE_URL",
    "CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED",
    "CLOUD_FUNCTION_SOURCE_OBJECT",
    "CLOUD_FUNCTION_SOURCE_MD5",
)


def _text(path):
    """Returns one document as text with normalised line endings."""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _flowed(text):
    """Returns text with every run of whitespace collapsed to a space.

    Prose in these documents is wrapped, so a phrase that spans a line
    break is one word sequence rather than two.
    """
    return re.sub(r"\s+", " ", text)


def _identifiers(text):
    """Returns every section and row number one document defines.

    A row number implies its parent sections, so ``35.1.1`` also makes
    ``35.1`` and ``35`` resolvable. That mirrors how a reader resolves a
    reference: naming a section is enough, whether or not it has a
    heading of its own.
    """
    found = set(HEADING_NUMBER.findall(text)) | set(ROW_NUMBER.findall(text))
    for value in list(found):
        parts = value.split(".")
        for cut in range(1, len(parts)):
            found.add(".".join(parts[:cut]))
    return found


def _slug(title):
    """Returns the fragment identifier a heading offers, as GitHub builds it.

    ``github-slugger`` lower-cases the rendered heading text, drops every
    punctuation and symbol character other than the hyphen and the
    underscore, and replaces **each** remaining space with a hyphen. The
    per-space rule is the part that is easy to get wrong: collapsing runs
    of whitespace instead produces a single hyphen where GitHub emits two,
    so a heading separated by " -- " (an em dash between two spaces, the
    dash dropped and both spaces surviving) resolves under this rule and
    not under a collapsing one.
    """
    rendered = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", title)
    rendered = rendered.replace("`", "").replace("*", "")
    slug = []
    for char in rendered.strip().lower():
        if char in ("-", "_"):
            slug.append(char)
        elif char == " ":
            slug.append("-")
        elif not unicodedata.category(char).startswith(("P", "S")):
            slug.append(char)
    return "".join(slug)


def _anchors(text):
    """Returns the fragment identifiers one document's headings offer.

    Only ATX headings outside fenced blocks count, so a shell comment in
    an extracted command cannot supply an anchor that masks a broken link.
    A repeated heading is suffixed the way GitHub disambiguates it.
    """
    anchors = set()
    occurrences = {}
    inside_fence = False
    for line in text.splitlines():
        if _FENCE.match(line):
            inside_fence = not inside_fence
            continue
        if inside_fence:
            continue
        heading = _HEADING.match(line)
        if heading is None:
            continue
        base = _slug(heading.group(1))
        seen = occurrences.get(base, 0)
        occurrences[base] = seen + 1
        anchors.add(base if seen == 0 else "%s-%d" % (base, seen))
    return anchors


def _section(path, heading, following):
    """Returns the text of one section, excluding the section after it."""
    text = _text(path)
    start = text.index(heading)
    return text[start:text.index(following, start)]


def _row_cells(section):
    """Returns each table row in one section as its list of cells."""
    rows = []
    for line in section.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|") or set(stripped) <= set("|- "):
            continue
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        rows.append(cells)
    return rows


def _backticked_paths(cell):
    """Returns the repository paths one table cell names.

    A path is a backticked token that carries a directory separator or a
    file extension, which admits ``setup.cfg`` at the repository root
    alongside every nested path and excludes prose in the same cell.
    """
    return {
        value
        for value in re.findall(r"`([^`]+)`", cell)
        if re.fullmatch(r"[\w./-]+", value) and ("/" in value or "." in value)
    }


def _links(path):
    """Returns the relative link targets one document carries.

    Anchors, absolute URLs and pure fragment references are excluded, so
    what is left is the set of repository paths the document claims.
    """
    targets = set()
    for match in re.finditer(r"\]\(([^)\s]+)\)", _text(path)):
        target = match.group(1).split("#")[0]
        if not target or target.startswith(("http://", "https://")):
            continue
        targets.add(target)
    return targets


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.name)
def test_every_document_is_present_and_non_empty(path):
    """Asserts each document the set refers to exists."""
    assert path.is_file(), path
    assert len(_text(path).strip()) > 500, path


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.name)
def test_every_relative_link_resolves(path):
    """Asserts no document points at a path that does not exist."""
    missing = [
        target
        for target in sorted(_links(path))
        if not (path.parent / target).resolve().exists()
    ]

    assert missing == [], (path.name, missing)


@pytest.mark.parametrize("subject", CREDENTIAL_SUBJECTS)
def test_the_runbook_covers_every_credential(subject):
    """Asserts the runbook's scope table names each credential."""
    text = _text(ROTATION_RUNBOOK)

    assert subject in text, subject


def test_the_runbook_declares_its_credential_scope():
    """Asserts the stated count matches the credentials covered."""
    text = _text(ROTATION_RUNBOOK)
    sections = re.findall(r"^### 3\.\d ", text, re.MULTILINE)

    assert "Seven credentials require operator action" in text
    assert len(sections) == len(CREDENTIAL_SUBJECTS)


@pytest.mark.parametrize(
    "path", DOCUMENTS_NAMING_THE_PROVIDER_KEY, ids=lambda p: p.name
)
def test_the_provider_key_exposure_is_recorded(path):
    """Asserts the log-borne exposure is named where it matters.

    The listing-provider key was never committed, so a document that
    describes the exposure only as committed values leaves it out.
    """
    text = _text(path)

    assert "zillow_service.py" in text
    assert "query" in text
    assert "log" in text


def test_the_runbook_states_the_provider_key_procedure():
    """Asserts the log-borne credential has all four steps."""
    text = _text(ROTATION_RUNBOOK)
    start = text.index("### 3.4 Listing-provider (Zillow) API key")
    section = text[start:text.index("### 3.5 ")]

    assert "**Revoke.**" in section
    assert "**Rotate.**" in section
    assert "**Delete from the stores that hold it.**" in section
    assert "**Review prior access.**" in section
    assert "developer console" in _flowed(section)
    assert "in a **header**" in _flowed(section)


def test_the_review_artefact_covers_the_provider_key():
    """Asserts the irreversible-operation review is exhaustive."""
    text = _text(CRITICAL_DECISIONS)
    start = text.index("## 1. Rotate the exposed credentials")
    section = text[start:text.index("## 2. ")]

    assert "five" in section
    assert "Zillow" in section
    assert "developer console" in _flowed(section)
    assert "purged" in section


def test_the_policy_separates_the_two_exposure_routes():
    """Asserts the policy does not describe every value as committed."""
    text = _text(SECURITY_POLICY)

    assert "Previously exposed credentials" in text
    assert "Never committed" in text
    assert "history rewrite addresses the first three" in _flowed(text)


@pytest.mark.parametrize("step", ROTATION_STEPS)
def test_the_rotation_order_is_stated_the_same_way(step):
    """Asserts the ordered sequence appears in every document."""
    for path in (ROTATION_RUNBOOK, CRITICAL_DECISIONS, SECURITY_POLICY):
        assert step.lower() in _text(path).lower(), (path.name, step)


def test_the_runbook_keeps_rotation_sequenced_last():
    """Asserts the irreversibility and the ordering both survive."""
    text = _text(ROTATION_RUNBOOK)

    assert "cannot be rolled back" in text
    assert "its own change window" in text
    assert "Revocation comes first" in text


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.name)
def test_every_section_and_row_reference_resolves(path):
    """Asserts no document cites a section or row that is not there.

    A citation is resolved against every document in the set rather than
    against the citing one alone, because these documents refer to each
    other in prose as often as by filename — "row 34.3.2 of the decision
    log" names no path. That still catches the failure this guards
    against, a citation whose target was never written: three such
    citations existed, and none of their targets resolved anywhere.

    References beginning ``0.`` address the Agent Action Plan, which is
    not part of this set, and are excluded rather than reported.

    A citation naming a section in :data:`REMOVED_SECTION_BAND` resolves
    through the rule the decision log publishes: the section 44 lower
    carries the same decision. Those citations are resolved that way here,
    so a reconciliation may name a removed identifier while a citation of
    something never written still fails.
    """
    defined = set()
    for other in DOCUMENTS:
        defined |= _identifiers(_text(other))

    def resolves(reference):
        if reference in defined:
            return True
        head, _, tail = reference.partition(".")
        if not head.isdigit():
            return False
        section = int(head)
        low, high = REMOVED_SECTION_BAND
        if not low <= section <= high:
            return False
        moved = str(section - REMOVED_SECTION_OFFSET)
        return (moved + "." + tail if tail else moved) in defined

    unresolved = sorted(
        {
            reference
            for paragraph in re.split(r"\n\s*\n", _text(path))
            for reference in RECORD_REFERENCE.findall(paragraph)
            if not reference.startswith(PLAN_SECTION_PREFIX)
            and not resolves(reference)
        }
    )

    assert unresolved == [], (path.name, unresolved)


def test_the_decision_log_publishes_the_rule_for_the_removed_band():
    """The band rule is stated, not assumed by this suite alone.

    A reader meeting a citation between 45 and 78 has to be able to
    resolve it from the document, and a reconciliation row has to record
    that the sections were removed rather than lost.
    """
    text = _text(DECISION_LOG)
    low, high = REMOVED_SECTION_BAND

    assert "Sections %d to %d" % (low, high) in text
    assert "subtract 44" in text.lower()
    assert "| 91.5.1 |" in text
    for section in range(low, high + 1):
        assert "\n## %d. " % section not in text, section


@pytest.mark.parametrize("path", DOCUMENTS, ids=lambda p: p.name)
def test_every_fragment_link_resolves(path):
    """Asserts no document links to a heading it does not contain.

    A fragment link that names a section which was never written renders
    as a link that goes nowhere, which is the failure a reader meets
    first and a path-only link check does not catch.
    """
    text = _text(path)
    available = _anchors(text)
    dangling = [
        fragment
        for fragment in FRAGMENT_LINK.findall(text)
        if fragment not in available
    ]

    assert dangling == [], (path.name, dangling)


@pytest.mark.parametrize("path", DELIVERED_ARTEFACTS, ids=lambda p: p.name)
def test_every_artefact_an_earlier_row_called_absent_exists(path):
    """Asserts the artefacts the withdrawn rows describe are present."""
    assert path.is_file(), path


@pytest.mark.parametrize("row", SUPERSEDED_ABSENCE_ROWS)
def test_the_withdrawal_names_every_row_it_supersedes(row):
    """Asserts each withdrawn row exists and is named by the withdrawal.

    The log revisits a superseded position rather than editing it, so a
    reader can meet one of these rows on its own. That is only safe while
    the withdrawal names it, so both properties are asserted together.
    """
    text = _text(DECISION_LOG)
    withdrawal = next(
        paragraph
        for paragraph in re.split(r"\n\s*\n", text)
        if WITHDRAWAL_ROW in paragraph and "withdrawn" in paragraph
    )

    assert row in _identifiers(text), row
    assert row in withdrawal, row


def test_the_matrix_carries_the_withdrawal_pointer():
    """Asserts the matrix does not restate an absence on its own.

    Its section 2.6 describes the earlier claim in the past tense, which
    is only accurate while the pointer to the withdrawal travels with it.
    """
    flowed = _flowed(_text(TRACEABILITY_MATRIX))

    assert "All eight rows above are delivered" in flowed
    assert WITHDRAWAL_ROW in flowed


def test_the_matrix_states_the_delivered_counts():
    """Asserts section 6 quotes one published total, not a rival one.

    It used to publish ``59 + 27 = 86`` while section 2.10 published 141,
    so a reader could take either and be wrong. Section 6 now states the
    figures that belong to its own tables and names section 2.10 for the
    delivered total.
    """
    section = _section(
        TRACEABILITY_MATRIX,
        "### 6.1 What this section counts",
        "### 6.2 ",
    )
    flowed = _flowed(section)

    assert "**{0}**".format(UNPLANNED_DELIVERED_PATHS) in section
    assert "**{0}**".format(LATER_ROUND_PATHS) in section
    assert "**{0}**".format(RETIRED_PATHS) in section
    assert "**{0}**".format(DELIVERED_PATHS) in section
    assert "{0} + {1} + {2} - {3} = {4}".format(
        PLANNED_CHANGED_PATHS,
        UNPLANNED_DELIVERED_PATHS,
        LATER_ROUND_PATHS,
        RETIRED_PATHS,
        DELIVERED_PATHS,
    ) in flowed


def test_the_matrix_enumerates_every_path_it_counts():
    """Asserts the enumerated paths match the stated count and exist.

    A count without an enumeration cannot be checked against the tree,
    which is the defect this section was added to remove.
    """
    created = _section(
        TRACEABILITY_MATRIX,
        "### 6.2 Created beyond the plan",
        "### 6.3 ",
    )
    changed = _section(
        TRACEABILITY_MATRIX,
        "### 6.3 A mode change",
        "### 6.4 ",
    )

    paths = set()
    for cells in _row_cells(created):
        if cells[0].isdigit():
            paths |= _backticked_paths(cells[1])
    for cells in _row_cells(changed):
        found = _backticked_paths(cells[0])
        if found:
            paths |= found

    assert len(paths) == UNPLANNED_DELIVERED_PATHS, sorted(paths)

    missing = [
        value
        for value in sorted(paths)
        if not (REPO_ROOT / value).exists()
    ]
    assert missing == [], missing


def test_the_matrix_reaches_the_same_set_from_the_finding_side():
    """Asserts both directions of section 6 cover one identical set.

    Adding a delivered path to one direction and forgetting the other is
    exactly the gap Rule 1's bidirectionality clause forbids, so the two
    sets are compared rather than each being counted alone.
    """
    forward = set()
    for heading, following in (
        ("### 6.2 Created beyond the plan", "### 6.3 "),
        ("### 6.3 A mode change", "### 6.4 "),
    ):
        section = _section(TRACEABILITY_MATRIX, heading, following)
        for cells in _row_cells(section):
            if cells[0].isdigit():
                forward |= _backticked_paths(cells[1])
            else:
                forward |= _backticked_paths(cells[0])

    reverse = set()
    for cells in _row_cells(
        _section(
            TRACEABILITY_MATRIX,
            "### 6.4 Twenty-seven of those paths",
            "### 6.5 ",
        )
    ):
        if len(cells) > 1:
            reverse |= _backticked_paths(cells[1])

    assert forward == reverse, sorted(forward ^ reverse)
    assert len(reverse) == UNPLANNED_DELIVERED_PATHS


def test_the_policy_points_at_the_itemised_inventory():
    """Asserts the policy republishes no count of its own.

    A total held in two documents drifts the moment either changes, and
    this one had: the policy quoted ten after the inventory stopped
    describing ten items.
    """
    flowed = _flowed(_text(SECURITY_POLICY))

    assert "Ten findings" not in flowed
    assert "\u00a735.1" in flowed
    assert "itemised inventory rather than as a count" in flowed
    assert "quotes no total" in flowed


@pytest.mark.parametrize("path", CONTACT_DOCUMENTS, ids=lambda p: p.name)
@pytest.mark.parametrize("placeholder", WITHDRAWN_CONTACTS)
def test_no_placeholder_is_offered_as_a_contact(path, placeholder):
    """Asserts a placeholder address is never published as reachable.

    Naming one while explaining that it was withdrawn is the point, so
    the value may appear in prose that calls it a placeholder. What it
    may not do is sit in a bullet or a table cell, which is how a reader
    reads a contact they are meant to use.
    """
    for paragraph in re.split(r"\n\s*\n", _text(path)):
        if placeholder not in paragraph:
            continue

        assert "placeholder" in _flowed(paragraph).lower(), placeholder
        for line in paragraph.splitlines():
            if placeholder in line:
                assert not line.lstrip().startswith(("-", "*", "|")), line


def test_the_policy_names_an_operator_prerequisite_per_channel():
    """Asserts each reporting channel says what makes it real.

    The two channels are in different states and each carries its own
    prerequisite: private reporting is off by default on a GitHub
    repository and is enabled here, so what it still needs is
    confirmation that a report filed through it is read, while no mailbox
    is provisioned at all. A policy that simply listed both would leave a
    reporter to assume the terms around them are settled.

    An earlier revision asserted the sentence "No monitored private
    channel is operational yet" here, and the policy carried it twice.
    That claim was measured false against this repository's own Security
    and quality tab, which carries the Report a vulnerability button, so
    what is asserted is now the separation the policy draws in its place
    -- an enabled channel, unverified monitoring, unauthorized terms.
    ``docs/security/DECISION_LOG.md`` row 104.6.1 owns the restatement.
    """
    flowed = _flowed(_text(SECURITY_POLICY))

    assert "No monitored private channel is operational yet" not in flowed
    assert "**Three things are in three different states here" in flowed
    assert "The **channel is enabled**" in flowed
    assert "**Monitoring is unverified**" in flowed
    assert "**The terms are unauthorized**" in flowed
    assert "**Confirmation that a private report is read.**" in flowed
    assert flowed.count("*Operator prerequisite:*") >= 2
    assert "is **off** by default" in flowed
    assert "No address is published here" in flowed


def test_the_policy_names_the_navigation_a_reporter_will_see():
    """Asserts the published route matches the provider's own names.

    A reporter following a tab or a settings page that is not on the
    screen concludes the channel is missing, and both names had moved:
    the tab reads "Security and quality" and the switch sits under
    "Advanced Security". The superseded spellings are asserted absent so
    a correction cannot be applied to one half only.

    The "No security policy detected" notice is separately required to be
    explained rather than left standing, because it is a statement about
    this file -- a policy is linked from a repository's default branch --
    and a reader who is not told that reads it as evidence the channel
    does not exist either.
    """
    flowed = _flowed(_text(SECURITY_POLICY))

    assert "**Security and quality** tab" in flowed
    assert "**Security** tab" not in flowed
    assert "**Advanced Security**" in flowed
    assert "Code security and analysis" not in flowed
    assert "*No security policy detected*" in flowed
    assert "default branch" in flowed


def test_both_documents_agree_on_what_the_channel_offers():
    """Asserts the readme does not overstate the policy it points at.

    The readme is where a reader meets the channel first, so a summary
    there that promised a monitored channel would be believed over the
    policy's own qualification. Both name the current tab, and the readme
    carries the same three-state split in one sentence.
    """
    readme = _flowed(_text(README))

    assert "**Security and quality** tab" in readme
    assert "**Security** tab" not in readme
    assert "channel is" in readme
    assert "has not been confirmed" in readme


def test_the_policy_publishes_no_response_commitment():
    """Asserts the response schedule is withdrawn, not advertised.

    A schedule is only meaningful once something receives the report, so
    the table survives as a proposal and is labelled as one.
    """
    text = _text(SECURITY_POLICY)
    flowed = _flowed(text)

    assert "No response times are committed" in flowed
    assert "Proposed target, not yet in force" in text
    assert "proposal, not a commitment" in flowed


@pytest.mark.parametrize("path", CONTACT_DOCUMENTS, ids=lambda p: p.name)
def test_the_guard_is_described_as_delivered(path):
    """Asserts the documented guard matches the workflow's guard.

    Both documents described a single grep over the whole backend tree
    that fails whenever reachability returns. The delivered guard is
    narrower in scope and has a second, semantic layer, and a reader
    relying on the old description would over-trust it.
    """
    text = _text(path)
    flowed = _flowed(text)

    assert GUARD_TEXTUAL_SCOPE in text
    assert "--include=*.py backend/\n" not in text
    assert "test_residual_risk_guards.py" in text
    assert "bypassable" in flowed
    assert "layer 2" in flowed.lower()


@pytest.mark.parametrize("path", CONTACT_DOCUMENTS, ids=lambda p: p.name)
def test_the_tolerated_job_is_named_as_gating_nothing(path):
    """Asserts a red build is explained rather than left ambiguous."""
    flowed = _flowed(_text(path))
    workflow = yaml.safe_load(_text(CI_WORKFLOW))
    tolerated = sorted(
        name
        for name, job in workflow["jobs"].items()
        if job.get("continue-on-error")
        or any(
            step.get("continue-on-error") for step in job.get("steps") or []
        )
    )

    #: The frontend job was once marked continue-on-error and expected to
    #: fail, so both documents had to say which red build gated nothing.
    #: It now passes and gates like every other job. The claim still has to
    #: be answered either way -- a reader meeting a red build needs to know
    #: whether it blocked the change -- so the documents must name the
    #: tolerated job while one exists, and say that none does once none
    #: remains.
    assert TOLERATED_JOB in flowed
    assert "continue-on-error" in flowed
    if tolerated:
        assert "gates nothing" in flowed, tolerated
    else:
        assert "No job in this pipeline is tolerated" in flowed


def test_the_readme_separates_enforced_gates_from_local_commands():
    """Asserts the verification table says which commands are gates.

    Running a command locally and having it block a change are different
    claims, and the readme previously made only the stronger one.
    """
    text = _text(README)
    flowed = _flowed(text)

    assert "Locally runnable is not the same as enforced" in flowed
    assert "**Enforced**" in text
    assert "Local only" in text
    assert "Integration gate" in text or "integration job" in flowed


@pytest.mark.parametrize("path", CONTACT_DOCUMENTS, ids=lambda p: p.name)
def test_the_frontend_is_described_as_non_operational(path):
    """Asserts neither document implies a working browser client."""
    flowed = _flowed(_text(path))

    assert "non-operational" in flowed
    assert "separately scoped" in flowed or "out of scope here" in flowed
    assert "Authorization" in flowed


@pytest.mark.parametrize("name", DEPLOYMENT_INPUTS)
def test_the_readme_documents_every_new_deployment_input(name):
    """Asserts an operator can find each input this work introduced.

    None of these existed before, so a deployment configured against the
    previous workflow has none of them, and the failure would surface at
    deployment time rather than at review time.
    """
    text = _text(README)

    assert name in text, name


def test_the_readme_records_the_renamed_location_input():
    """Asserts the rename is stated, not silently substituted."""
    flowed = _flowed(_text(README))

    assert "replaces `GKE_CLUSTER_ZONE`" in flowed
    assert "`jq`" in flowed


@pytest.mark.parametrize("row", SUPERSEDED_REPAIR_ROWS)
def test_the_withdrawn_repair_names_every_row_it_supersedes(row):
    """Asserts each superseded row exists and is marked where it stands.

    The first repair for the pool-exhaustion finding was delivered and
    then measured not to work. Following the convention section 27
    established, the rows that decided it keep their own chronology
    rather than being rewritten, which is only safe while each carries
    the pointer and the withdrawal names it back.
    """
    text = _text(DECISION_LOG)
    withdrawal = _flowed(
        text.split(REPAIR_WITHDRAWAL_HEADING)[-1]
    )

    assert row in _identifiers(text), row
    assert row in withdrawal, row
    marked = next(
        line
        for line in text.splitlines()
        if line.startswith("| %s |" % row)
    )
    assert REPAIR_WITHDRAWAL_SECTION in marked, row
    assert "superseded" in marked.lower(), row


def test_the_withdrawn_repair_publishes_what_falsified_it():
    """Asserts the measurement is recorded, not just the conclusion.

    Rule 1 makes this log the authority for why, and "it did not work"
    is only followable while the figures that showed it are beside it.
    """
    flowed = _flowed(_text(DECISION_LOG))

    for figure in FALSIFYING_FIGURES:
        assert figure in flowed, figure


def test_the_matrix_carries_the_withdrawn_repair_pointer():
    """Asserts the matrix does not restate the withdrawal on its own."""
    flowed = _flowed(_text(TRACEABILITY_MATRIX))

    assert REPAIR_WITHDRAWAL_SECTION in flowed
    assert "worker-thread cap" in flowed
