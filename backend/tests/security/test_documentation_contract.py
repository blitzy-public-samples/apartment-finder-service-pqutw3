"""Checks over the delivered documents and the executive presentation.

A document cannot be compiled, so nothing else in this suite reports when one
of them says something the tree contradicts. These cases do. They are limited
to claims that are mechanically checkable against the tree -- a command a
reader would run, a count, a path, a contact, a structural property of the
presentation -- and assert nothing about prose.

What is asserted:

* no onboarding document tells a reader to generate a secret onto a terminal.
  A value written to standard output is captured by shell history, by terminal
  scrollback and by any session recording, so every generator is paired with a
  redirect into a file the same command restricts
* the rotation runbook names a procedure for removing a value from history and
  a way to verify it, covering the places a force-push does not reach
* the disclosure contacts are a single alias rather than a person, and no
  personal placeholder survives anywhere
* the runtime pin inventory names every site that actually pins the runtime,
  derived from those files rather than from the document
* every numbered subsection of the decision log belongs to the section it sits
  in, so a cross-reference resolves
* the documents earlier decision rows record as absent exist, and the rows and
  the matrix paragraph that recorded their absence are superseded rather than
  quietly rewritten
* the presentation keeps its structure -- eighteen slides, both diagrams, every
  icon -- while its remote assets carry an integrity hash and its document
  carries an origin policy that names every host it fetches from
* the presentation's architecture claims match what the infrastructure
  delivers: the removed event stream appears nowhere, and the secret-delivery
  path it draws is the one that exists

The tree is the authority throughout: pin sites are read from the files that
pin, the delivery labels from the Terraform and manifest names, and the
presentation's counts from the presentation itself.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import re

import pytest
from conftest import REPO_ROOT

from backend.app.core.config import Settings

#: Committed environment template.
ENVIRONMENT_EXAMPLE = REPO_ROOT / ".env.example"

#: Project readme.
README = REPO_ROOT / "README.md"

#: Disclosure policy.
SECURITY_POLICY = REPO_ROOT / "SECURITY.md"

#: Rotation runbook.
ROTATION = REPO_ROOT / "docs" / "security" / "CREDENTIAL_ROTATION.md"

#: Decision log, the authority Rule 1 makes it.
DECISION_LOG = REPO_ROOT / "docs" / "security" / "DECISION_LOG.md"

#: Traceability matrix.
TRACEABILITY = REPO_ROOT / "docs" / "security" / "TRACEABILITY_MATRIX.md"

#: Residual-risk register.
RESIDUAL_RISK = REPO_ROOT / "docs" / "security" / "RESIDUAL_RISK.md"

#: Reviewer-facing decision summary, at the path its Rule names.
CRITICAL_DECISIONS = REPO_ROOT / "docs" / "review" / "CRITICAL_DECISIONS.md"

#: Executive presentation.
DECK = REPO_ROOT / "blitzy-deck" / "executive-summary.html"

#: The documents an operator follows to bring an environment up. Only these
#: are scanned for generation commands: a decision row describing a value in
#: prose is not an instruction to run anything.
ONBOARDING_DOCUMENTS = (ENVIRONMENT_EXAMPLE, README, ROTATION)

#: Documents whose earlier text recorded the deliverables as absent, and which
#: must therefore all exist for that record to have been superseded.
DELIVERED_DOCUMENTS = (
    TRACEABILITY,
    RESIDUAL_RISK,
    ROTATION,
    CRITICAL_DECISIONS,
    DECK,
)

#: Every file whose terminal newline is asserted here.
DOCUMENT_FILES = (
    ENVIRONMENT_EXAMPLE,
    README,
    SECURITY_POLICY,
    ROTATION,
    DECISION_LOG,
    TRACEABILITY,
    DECK,
)

#: One command that produces a secret value.
GENERATOR = re.compile(
    r"secrets\.token_urlsafe|secrets\.token_hex|secrets\.choice"
    r"|openssl\s+rand"
)

#: One form that sends a produced value into a file rather than to a terminal.
REDIRECT = re.compile(r">>|--data-file|umask")

#: Lines a generator's command may span, counted from the matching line.
COMMAND_WINDOW = 3

#: Contacts no document may carry. Each names a person or an unfilled field.
FORBIDDEN_CONTACTS = (
    "your.email@example.com",
    "Your Name",
    "your-username",
    "Your GitHub Profile",
)

#: The one destination the disclosure policy sends a reporter to, named the
#: same way in both documents. An email alias was considered and rejected:
#: every candidate sat in a reserved example domain, which can receive no
#: mail, so publishing one would send a reporter nowhere while appearing to
#: offer a channel -- the same defect FORBIDDEN_CONTACTS above forbids.
#: SECURITY.md argues that out and names the repository's private advisory
#: channel instead, and README.md points at the same one.
SECURITY_CHANNEL = (
    "private vulnerability reporting",
    "Report a vulnerability",
)

#: The interpreter version every pin site declares.
PINNED_PYTHON = "3.9"

#: Where the runtime is pinned, and the text that pins it. The inventory in the
#: disclosure policy is asserted against these paths, and each is confirmed to
#: still carry its pin, so neither the document nor this table can drift from
#: the tree alone. The delivery workflow is not among them: it sets up no
#: interpreter of its own, calling the reusable `.github/workflows/ci.yml`
#: instead, so the version is declared once and both workflows run against
#: that one declaration -- declaring it twice is what would let them drift.
#: The fifth site the policy lists is CODE_LEVEL_PIN below, a language
#: construct rather than a version declaration, asserted separately.
PIN_SITES = {
    "infrastructure/docker/Dockerfile.backend": "python:3.9-slim",
    ".github/workflows/ci.yml": "python-version: '3.9'",
    "infrastructure/terraform/main.tf": 'runtime     = "python39"',
    "scripts/deploy.sh": "--runtime python39",
}

#: The code-level constraint that makes the pin load-bearing rather than
#: conventional, stated separately from the version declarations.
CODE_LEVEL_PIN = "@asyncio.coroutine"

#: Decision rows that recorded the deliverables as absent. One row
#: supersedes all five.
SUPERSEDED_ABSENCE_ROWS = ("26.19", "29.11", "30.15", "32.12", "33.11")

#: The row that supersedes them. It was numbered 35.26 when it was written
#: and is delivered as 35.1.1; DECISION_LOG section 87 records the
#: concordance, and 35.26 now carries an unrelated row.
SUPERSEDING_ROW = "35.1.1"

#: Rows whose claim about the system a later row made untrue. Each states
#: a decision that still stands, so the row is left as it was written and
#: the claim is withdrawn by the section named below. A reader landing on
#: one of these first has to be able to reach the withdrawal from it.
#:
#: Two entries have been removed rather than fixed. The log carried its
#: sections 1 to 34 a second time as sections 45 to 78, so rows 50.14 and
#: 59.4 were byte-identical re-issues of 6.14 and 15.4 and were named here
#: alongside them. Consolidating the log to one copy removed the duplicate
#: half, which leaves each withdrawn claim asserted exactly once, at the
#: row that made it.
SUPERSEDED_BEHAVIOUR_ROWS = (
    "6.14",
    "15.4",
    "81.10",
    "81.39",
    "84.6.3",
    "38.7",
    "86.1.2",
    "43.5.6",
    "82.16",
    "83.16",
    "86.5.8",
    #: Two rows about one Terraform input, each untrue of the delivered
    #: tree and in opposite directions: one reported the input as removed
    #: when it was declared and required, the other described a
    #: cross-variable validation a later round replaced with a created VPC.
    "37.1",
    "42.2.6",
)

#: The section that withdraws those claims and names each row it withdraws
#: one from.
WITHDRAWING_SECTION = "## 89."

#: Every published document a reviewer reads, plus the two workflow files
#: whose comments are read the same way. A claim about the tree is checked
#: wherever it is made, not only in the two Rule 1 artifacts.
PUBLISHED_RECORD = (
    DECISION_LOG,
    RESIDUAL_RISK,
    TRACEABILITY,
    ROTATION,
    CRITICAL_DECISIONS,
    README,
    SECURITY_POLICY,
    DECK,
    REPO_ROOT / ".github" / "workflows" / "ci.yml",
    REPO_ROOT / ".github" / "workflows" / "cd.yml",
)

#: Constructs the Terraform configuration deliberately does not declare,
#: because the finding that asks for them is reported for confirmation
#: rather than closed. Read from the configuration below, so the document
#: rule that follows is enforced only while the tree matches.
DEFERRED_TERRAFORM_CONSTRUCTS = (
    "required_version",
    "required_providers",
)

#: The provider lock that would pin the resolution those constructs
#: constrain. It is untracked and absent.
DEFERRED_TERRAFORM_LOCK = (
    REPO_ROOT / "infrastructure" / "terraform" / ".terraform.lock.hcl"
)

#: Statements that assert the deferred constructs are present. Each was
#: made by a published document while the tree carried none of them, which
#: is what makes them the phrasings worth matching rather than a
#: hypothetical set. Matched against the whitespace-collapsed form of one
#: statement unit, so a hard-wrapped sentence is read whole.
TERRAFORM_PRESENCE_CLAIMS = (
    "The constraint exists",
    "carries a `terraform` block with",
    "carries a `terraform` block and",
    "`.terraform.lock.hcl` is tracked",
    "keep `.terraform.lock.hcl` tracked",
    "Keep the `terraform` block",
    "satisfies the definition's own `required_version",
    "required_version` constraint `infrastructure/terraform/main.tf` declares",
    "required_version constraint infrastructure/terraform/main.tf declares",
    "a provider constraint and a tracked lock were",
    "and are authorized at row 94.8.3",
)

#: Words that mark a statement as a record of a position no longer held.
#: Deliberately narrow: a statement that merely mentions something being
#: open, reported or no longer true is still asserting its own content,
#: which is exactly how the defect this case exists for was written.
WITHDRAWAL_MARKERS = (
    "withdraw",
    "Withdraw",
    "WITHDRAWN",
    "reverted",
    "Reverted",
    "was wrong about the tree",
)

#: Values an operator must provision that no bootstrap can supply.
PROVIDER_CREDENTIALS = (
    "ZILLOW_API_KEY",
    "PAYPAL_CLIENT_ID",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "SENDGRID_API_KEY",
)

#: The bootstrap both onboarding documents name.
BOOTSTRAP_COMMAND = "scripts/setup_dev_environment.sh"

#: The two required settings the bootstrap produces itself. Every other
#: required setting is a provider credential no bootstrap can invent, which is
#: how the enumeration above is derived rather than transcribed.
BOOTSTRAP_SUPPLIED = ("DATABASE_URL", "SECRET_KEY")

#: Lines of a template within which a reader looks for how to use it.
LEADING_REGION_LINES = 30

#: The sentence that introduces the credentials still to be provisioned, and
#: the number words it may use. A count that disagrees with the list beneath it
#: is how a reader ends up believing one integration fewer needs attention.
PROVISIONING_SENTENCE = re.compile(
    r"(\w+)(?:\s+further)? values still need real provisioning"
)
NUMBER_WORDS = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
}

#: Claim the presentation may no longer make: five values have no default that
#: works, so a reader told otherwise would stop at a startup refusal.
RETIRED_ONBOARDING_CLAIM = "every setting has a safe local default"

#: Slides, diagrams and icon placeholders the presentation must keep.
DECK_SLIDES = 18
DECK_DIAGRAMS = 2
DECK_ICONS = 44

#: Remote assets the presentation fetches that must carry an integrity hash,
#: by the substring identifying each.
INTEGRITY_PINNED_ASSETS = (
    "reveal.js@5.1.0/dist/reveal.css",
    "reveal.js@5.1.0/dist/reveal.js",
    "lucide@0.460.0/dist/umd/lucide.min.js",
)

#: Module whose hash is declared in the import map instead, because that is
#: where a module's integrity belongs.
IMPORT_MAP_ASSET = "mermaid@11.4.0/dist/mermaid.esm.min.mjs"

#: Hosts the presentation may reach, each of which the policy must name.
DECK_HOSTS = (
    "https://cdn.jsdelivr.net",
    "https://fonts.googleapis.com",
    "https://fonts.gstatic.com",
)

#: Nodes the architecture diagram must carry, naming the delivery that exists.
DELIVERY_LABELS = (
    "Managed Secret",
    "Per-Secret",
    "Read Grant",
    "Workload",
    "Identity",
    "Upgrade Job",
)

#: Node the diagram must not carry: nothing publishes to a stream, subscribes
#: to one, or is triggered by one, and none is provisioned.
REMOVED_NODE = "Event Stream"

#: The delivery chain the diagram must draw, as consecutive edges. The arrows
#: are HTML-escaped in the diagram source because it is embedded in markup.
DELIVERY_EDGES = (
    ("VAULT", "GRANT"),
    ("GRANT", "IDENT"),
    ("IDENT", "API"),
    ("IDENT", "INGEST"),
    ("IDENT", "MIG"),
)

#: The nodes the diagram marks as hardened, which must include the three the
#: delivery chain adds -- a drawn path that is not marked reads as incidental.
HARDENED_NODES = ("VAULT", "GRANT", "IDENT")

#: Statements the presentation's onboarding and configuration slides must
#: carry, so that a reader is not told the template alone is sufficient.
DECK_ONBOARDING_CLAIMS = (
    "setup script",
    "five provider credentials",
)

#: The two asset residuals the presentation retains rather than closes. Rule 1
#: puts a residual's reasoning in the decision log, so that is where each is
#: asserted rather than in a comment inside the presentation itself.
DECK_RESIDUALS = (
    "the typeface stylesheet is negotiated per browser so no hash describes"
    " it",
    "import-map integrity is a recent addition that an older browser ignores",
)

#: One markdown heading, by level and text.
HEADING = re.compile(r"(?m)^(#{2,3})\s+(\S+)")


def _text(path):
    """Return one file's source."""
    return path.read_text(encoding="utf-8")


#: A line that begins a statement of its own: a markdown table row or a
#: list item. A table row is one statement, and so is a bullet -- a
#: withdrawal marker on one must not exempt the one beside it, which is
#: how the seventh occurrence of the defect below escaped an earlier
#: revision of this case that split on blank lines alone.
STATEMENT_START = re.compile(r"^(\||[*+-]\s|\d+\.\s)")


def _statement_units(text):
    """Return each table row, list item and hard-wrapped paragraph.

    Prose is returned a paragraph at a time, because these documents wrap
    and a marker opening a paragraph governs the sentences under it. A
    table row or a list item ends the paragraph before it and starts one of
    its own, and its own continuation lines are folded into it.

    A leading ``#`` is dropped from each line before the unit is joined, so
    that a sentence written across the lines of a YAML comment block reads
    as the sentence it is rather than as fragments separated by markers.
    """
    collected = []
    buffer = []

    def flush():
        if buffer:
            collected.append(" ".join(" ".join(buffer).split()))
            del buffer[:]

    for raw in text.replace("\r\n", "\n").split("\n"):
        stripped = raw.lstrip()
        if stripped.startswith("#"):
            line = stripped.lstrip("#").strip()
        else:
            line = raw
        if not line.strip():
            flush()
        elif STATEMENT_START.match(line.lstrip()):
            flush()
            buffer.append(line)
        else:
            buffer.append(line)
    flush()
    return collected


def test_the_terraform_constructs_the_tree_defers_are_absent_from_it():
    """The configuration declares neither construct and locks nothing.

    This is the measurement the case below rests on. Asserting the document
    rule without it would leave the rule in force after an authorized
    change had legitimately added the constructs.
    """
    configuration = _text(
        REPO_ROOT / "infrastructure" / "terraform" / "main.tf"
    )

    for construct in DEFERRED_TERRAFORM_CONSTRUCTS:
        assert construct not in configuration, construct
    assert not re.search(r"(?m)^terraform\s*\{", configuration)
    assert not DEFERRED_TERRAFORM_LOCK.exists(), DEFERRED_TERRAFORM_LOCK


@pytest.mark.parametrize(
    "path", PUBLISHED_RECORD, ids=lambda path: path.name
)
def test_no_document_states_the_deferred_constructs_are_present(path):
    """A presence claim stands only where it is marked withdrawn.

    Four documents asserted that the configuration declared a provider
    version constraint and that the lock was tracked, while the tree
    carried neither and two delivered cases asserted their absence. One of
    those assertions reported half of a confirmation-only finding as
    closed, which is the shape a reviewer acts on: it invites them to
    decline authorizing a fix that is still needed.

    What is asserted is not that the phrasings never appear -- the
    withdrawn rows quote them, and must, because the record of a position
    held is what makes a correction reviewable. It is that every statement
    unit making one carries a withdrawal marker of its own.
    """
    standing = [
        (claim, unit[:160])
        for unit in _statement_units(_text(path))
        for claim in TERRAFORM_PRESENCE_CLAIMS
        if claim in unit
        and not any(marker in unit for marker in WITHDRAWAL_MARKERS)
    ]
    assert standing == [], (path.name, standing)


def test_the_flagged_terraform_finding_is_recorded_as_fully_open():
    """Both halves of it are open, and the row says so.

    The row that reports it is the one a reviewer reads to decide whether
    the finding still needs authorizing, so an understated row there is
    worse than no row at all.
    """
    rows = [
        line
        for line in _text(DECISION_LOG).splitlines()
        if line.startswith("| 5 |")
        and "remote state backend" in line
    ]

    assert len(rows) == 1, rows
    assert "Fully open, both halves" in rows[0]
    assert "96.1.1" in rows[0]


def _generation_commands(path):
    """Yield ``(line_number, window)`` for each generator in one document.

    The window is the matching line and the two that follow it, because a
    command that produces a value and the redirect that captures it are
    routinely written across a continuation.
    """
    lines = _text(path).splitlines()
    for index, line in enumerate(lines):
        if GENERATOR.search(line):
            window = lines[index:index + COMMAND_WINDOW]
            yield index + 1, "\n".join(window)


@pytest.mark.parametrize(
    "path", ONBOARDING_DOCUMENTS, ids=lambda path: path.name
)
def test_no_document_generates_a_secret_onto_a_terminal(path):
    """Every generator writes into a file the command restricts."""
    rendered = [
        (line, window)
        for line, window in _generation_commands(path)
        if not REDIRECT.search(window)
    ]
    assert rendered == [], (path.name, rendered)


@pytest.mark.parametrize(
    "path", ONBOARDING_DOCUMENTS, ids=lambda path: path.name
)
def test_each_document_carries_at_least_one_generation_command(path):
    """The case above is not passing because it found nothing to check."""
    assert list(_generation_commands(path)), path.name


def test_the_runbook_names_a_history_procedure_and_its_verification():
    """Removing a value from history is a procedure, not an instruction."""
    body = _text(ROTATION)

    assert "### 3.5" in body
    assert "### 4.7" in body

    for required in (
        "git for-each-ref",
        "refs/stash",
        "filter-repo",
        "reflog expire",
        "--prune",
        "git cat-file --batch-all-objects",
    ):
        assert required in body, required


def test_the_runbook_covers_what_a_force_push_cannot_reach():
    """A completed-looking rewrite leaves copies in four other places."""
    body = _text(ROTATION)

    for required in (
        "refs/pull",
        "Forks",
        "Mirrors",
        "Re-clone is mandatory",
    ):
        assert required in body, required


@pytest.mark.parametrize(
    "path", (SECURITY_POLICY, README), ids=lambda path: path.name
)
def test_no_document_carries_a_personal_placeholder_contact(path):
    """A contact names an alias, so a maintainer changing breaks nothing."""
    body = _text(path)
    present = [name for name in FORBIDDEN_CONTACTS if name in body]
    assert present == [], (path.name, present)


@pytest.mark.parametrize(
    "path", (SECURITY_POLICY, README), ids=lambda path: path.name
)
def test_each_document_names_the_one_security_alias(path):
    """Both documents point a reporter at the same destination."""
    body = _text(path)

    for named in SECURITY_CHANNEL:
        assert named in body, (path.name, named)


def test_the_runtime_pin_inventory_names_every_site_that_pins():
    """The inventory is asserted against the files, not against itself."""
    body = _text(SECURITY_POLICY)

    for path, pin in PIN_SITES.items():
        assert pin in _text(REPO_ROOT / path), (path, pin)
        assert path in body, path

    #: Every path the policy presents with a version is one of these four.
    #: The construct row carries no version, so it is not matched here.
    presented = set(re.findall(r"`([^`]+)` \| `[^`]*3\.?9[^`]*`", body))
    assert presented <= set(PIN_SITES), sorted(presented - set(PIN_SITES))
    assert len(presented) == len(PIN_SITES), sorted(presented)


def test_the_policy_states_the_code_level_constraint_separately():
    """The decorator is why advancing the runtime is a code change."""
    body = _text(SECURITY_POLICY)
    assert CODE_LEVEL_PIN in body
    assert "listing_updater.py" in body


def test_the_code_level_constraint_is_still_present():
    """The statement above describes the tree rather than history."""
    updater = REPO_ROOT / "backend" / "app" / "tasks" / "listing_updater.py"
    assert CODE_LEVEL_PIN in _text(updater)


def test_every_numbered_subsection_belongs_to_its_section():
    """A subsection numbered for another section resolves to nothing."""
    section = None
    misplaced = []
    for level, opening in HEADING.findall(_text(DECISION_LOG)):
        number = opening.rstrip(".")
        if level == "##":
            section = number
            continue
        if "." not in number:
            continue
        prefix = number.split(".")[0]
        if not prefix.isdigit():
            continue
        if section is not None and prefix != section:
            misplaced.append((section, number))
    assert misplaced == [], misplaced


@pytest.mark.parametrize(
    "path", DELIVERED_DOCUMENTS, ids=lambda path: path.name
)
def test_each_recorded_deliverable_is_present(path):
    """The absence the superseded rows recorded no longer holds."""
    assert path.is_file(), path
    assert _text(path).strip(), path.name


def test_the_absence_rows_are_superseded_rather_than_rewritten():
    """Each earlier row stands, and one row withdraws all five."""
    body = _text(DECISION_LOG)

    for row in SUPERSEDED_ABSENCE_ROWS:
        assert "| " + row + " |" in body, row

    superseding = [
        line
        for line in body.splitlines()
        if line.startswith("| " + SUPERSEDING_ROW + " |")
    ]
    assert len(superseding) == 1, superseding
    for row in SUPERSEDED_ABSENCE_ROWS:
        assert row in superseding[0], row


def test_each_withdrawn_claim_names_the_row_that_made_it():
    """Every withdrawn claim stands where written and is named in one place.

    The alternative to naming them is a log that reads as though it had
    always described the delivered system, which loses what was believed
    when each decision was taken. A row named nowhere in the withdrawing
    section is a claim a reader would still take as current.
    """
    body = _text(DECISION_LOG)
    section = body[body.index(WITHDRAWING_SECTION):]

    for row in SUPERSEDED_BEHAVIOUR_ROWS:
        assert "| " + row + " |" in body, row
        assert row in section, row


def test_the_matrix_no_longer_records_the_deliverables_as_absent():
    """Its paragraph is superseded in place and points at the log.

    The correction was once stated twice, in two paragraphs naming four
    withdrawn rows in one and five in the other. One paragraph naming all
    five replaces both, so what is asserted here is the property rather
    than the sentence: the absence claim is gone, the record of it having
    been made is kept, and the withdrawing row is named.
    """
    body = _text(TRACEABILITY)
    #: The prose is hard-wrapped, so a sentence is matched against the
    #: whitespace-collapsed form rather than around a line break.
    flowed = " ".join(body.split())
    assert "were not yet present in this working tree" not in body
    assert "stays visible rather than being" in flowed
    assert "recorded five of those paths as absent" in flowed
    assert SUPERSEDING_ROW in body


def test_this_round_is_recorded_with_its_own_traceability():
    """A round's decisions and its finding mapping are both recorded."""
    body = _text(DECISION_LOG)
    assert "## 35." in body
    #: The subsection was numbered 35.6 when it was written and is
    #: delivered as 35.13. The ordinal is not the property worth
    #: asserting -- that the round's own finding mapping is recorded
    #: inside its own section is -- so this reads the property, which a
    #: later insertion into section 35 cannot silently break.
    assert re.search(
        r"(?m)^### 35\.\d+ Traceability for this round$", body
    ), "section 35 records no traceability subsection"


@pytest.mark.parametrize(
    "path", (ENVIRONMENT_EXAMPLE, README), ids=lambda path: path.name
)
def test_each_document_names_the_supported_bootstrap(path):
    """A reader is pointed at the one route that produces a working file."""
    assert BOOTSTRAP_COMMAND in _text(path), path.name


def test_the_template_leads_with_the_supported_bootstrap():
    """A reader consulting the usage block finds the route that works."""
    leading = _text(ENVIRONMENT_EXAMPLE).splitlines()[:LEADING_REGION_LINES]
    assert any(BOOTSTRAP_COMMAND in line for line in leading), leading[:5]


def test_the_readme_presents_the_bootstrap_before_the_manual_fallback():
    """The hand-copy path is the alternative, not the headline."""
    body = _text(README)
    generator = GENERATOR.search(body)
    assert generator is not None
    assert body.index(BOOTSTRAP_COMMAND) < generator.start()


@pytest.mark.parametrize(
    "path", (ENVIRONMENT_EXAMPLE, README), ids=lambda path: path.name
)
def test_each_document_enumerates_what_must_still_be_provisioned(path):
    """No bootstrap supplies a provider credential, and both say so."""
    body = _text(path)
    for name in PROVIDER_CREDENTIALS:
        assert name in body, (path.name, name)


def test_the_enumeration_is_what_the_bootstrap_cannot_supply():
    """The list is derived from the settings, not transcribed beside them."""
    required = set(
        name
        for name, field in Settings.__fields__.items()
        if field.required
    )
    assert set(PROVIDER_CREDENTIALS) == required - set(BOOTSTRAP_SUPPLIED)
    for name in BOOTSTRAP_SUPPLIED:
        assert name in required, name


@pytest.mark.parametrize(
    "path", (ENVIRONMENT_EXAMPLE, README), ids=lambda path: path.name
)
def test_each_document_counts_the_credentials_it_then_lists(path):
    """A count one short reads as one integration fewer to attend to."""
    stated = PROVISIONING_SENTENCE.search(_text(path))
    assert stated is not None, path.name
    word = stated.group(1).lower()
    assert word in NUMBER_WORDS, (path.name, word)
    assert NUMBER_WORDS[word] == len(PROVIDER_CREDENTIALS), (path.name, word)


def test_the_presentation_makes_no_claim_of_a_working_default():
    """Five settings have no default that works; the slide said they did."""
    assert RETIRED_ONBOARDING_CLAIM not in _text(DECK)


def test_the_presentation_keeps_its_structure():
    """Eighteen slides, both diagrams and every icon survive the change."""
    body = _text(DECK)

    assert body.count("<section") == DECK_SLIDES
    assert body.count("</section>") == DECK_SLIDES
    assert body.count('class="mermaid"') == DECK_DIAGRAMS
    assert len(re.findall(r"<i\s+data-lucide=", body)) == DECK_ICONS


@pytest.mark.parametrize("asset", INTEGRITY_PINNED_ASSETS)
def test_each_remote_asset_is_pinned_to_the_bytes_reviewed(asset):
    """A delivery network serving other content is refused, not executed."""
    tag = [
        line
        for line in _text(DECK).splitlines()
        if asset in line and ("<script" in line or "<link" in line)
    ]
    assert len(tag) == 1, (asset, tag)
    assert re.search(r'integrity="sha384-[A-Za-z0-9+/]+=*"', tag[0]), tag[0]
    assert 'crossorigin="anonymous"' in tag[0], tag[0]


def test_the_diagram_module_carries_its_hash_in_the_import_map():
    """A module's integrity is declared where a module is resolved."""
    body = _text(DECK)

    assert 'type="importmap"' in body
    opening = body.index('type="importmap"')
    closing = body.index("</script>", opening)
    mapping = body[opening:closing]

    assert IMPORT_MAP_ASSET in mapping
    assert re.search(r'"sha384-[A-Za-z0-9+/]+=*"', mapping), mapping
    assert '"integrity"' in mapping

    #: The specifier is bare, so resolution goes through the map above and
    #: the hash applies. A full URL in the import would bypass it. The
    #: import is dynamic, which resolves through the same map and keeps a
    #: fetch failure from discarding the module that starts the deck.
    assert "import('mermaid')" in body
    assert not re.search(r"import[\s(]+['\"]https://", body)
    assert not re.search(r"from\s+['\"]https://", body)


def test_the_presentation_restricts_the_origins_it_may_reach():
    """An asset compromised beyond a hash still cannot pull or send."""
    body = _text(DECK)

    policy = re.search(
        r'http-equiv="Content-Security-Policy"\s+content="([^"]+)"', body
    )
    assert policy is not None, "the document declares no policy"
    directives = policy.group(1)

    assert "default-src 'none'" in directives
    assert "connect-src 'none'" in directives
    assert "base-uri 'none'" in directives
    assert "form-action 'none'" in directives

    #: Every host the document fetches from is named by the policy, so the
    #: policy cannot be stricter than the document needs.
    for host in DECK_HOSTS:
        assert host in body, host
        assert host in directives, host

    #: And no other host is fetched from.
    fetched = set(
        re.findall(r'(?:src|href)="(https://[^/"]+)', body)
    ) | set(re.findall(r"from '(https://[^/']+)", body))
    assert fetched <= set(DECK_HOSTS), sorted(fetched - set(DECK_HOSTS))


@pytest.mark.parametrize("label", DELIVERY_LABELS)
def test_the_architecture_names_the_delivery_that_exists(label):
    """The drawn secret path is the one the infrastructure creates."""
    assert label in _text(DECK), label


@pytest.mark.parametrize("source,target", DELIVERY_EDGES)
def test_the_architecture_draws_the_delivery_chain(source, target):
    """A named node is not a path: the edges between them are asserted."""
    edge = (
        re.escape(source)
        + r'(?:\["[^"]*"\])?\s*--&gt;\s*'
        + re.escape(target)
    )
    assert re.search(edge, _text(DECK)), (source, target)


@pytest.mark.parametrize("node", HARDENED_NODES)
def test_each_delivery_node_is_marked_hardened(node):
    """The chain is drawn as a control, not as incidental plumbing."""
    marked = re.search(r"class ([A-Z,]+) hardened;", _text(DECK))
    assert marked is not None
    assert node in marked.group(1).split(","), marked.group(1)


def test_the_architecture_draws_no_resource_that_was_removed():
    """Nothing publishes to a stream, and none is provisioned."""
    body = _text(DECK)
    assert REMOVED_NODE not in body
    assert "STREAM" not in body


@pytest.mark.parametrize("claim", DECK_ONBOARDING_CLAIMS)
def test_the_presentation_states_how_an_environment_is_brought_up(claim):
    """The route that works, and the values it cannot supply."""
    assert claim in _text(DECK), claim


@pytest.mark.parametrize("residual", DECK_RESIDUALS)
def test_the_presentation_states_each_retained_asset_residual(residual):
    """An unpinnable asset is recorded, not left to be discovered."""
    collapsed = re.sub(r"\s+", " ", _text(DECISION_LOG))
    assert re.sub(r"\s+", " ", residual) in collapsed, residual


@pytest.mark.parametrize("path", DOCUMENT_FILES, ids=lambda path: path.name)
def test_each_document_ends_with_exactly_one_newline(path):
    """A file without a final newline appends to the next line read."""
    body = path.read_bytes()
    assert body.endswith(b"\n"), path.name
    assert not body.endswith(b"\n\n"), path.name
