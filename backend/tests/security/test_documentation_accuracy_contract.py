"""Checks over the claims the project's own documents make.

A document cannot be compiled, so a claim in one can drift from the code
it describes without anything failing. The cases here cover the claims
that can be checked mechanically, which are the ones most likely to go
stale: a command named as automated that nothing automates, a contact
address that reaches nobody, a link to a file that has moved, and a
description of configuration that the configuration no longer matches.

What is asserted:

* no published contact is a placeholder, in either document
* every relative link resolves to a file or directory that exists
* every command the README presents as a verification gate is invoked by
  the continuous-integration workflow, so the claim that all of them run
  there is true rather than aspirational
* every job the README names in its continuous-integration table exists
  in the workflow, and vice versa
* the README's description of how the environment file is chosen matches
  what ``backend.app.core.config`` implements
* every figure the traceability matrix publishes about the schema -- its
  totals, the provenance split between the columns this work introduces
  and the columns that precede it, and the two enumerations that list
  them -- equals the figure derived from ``Base.metadata`` and from
  revision ``0001``

``backend.app.core.config`` is the authority for the configuration
claims, ``.github/workflows/ci.yml`` is the authority for what is
automated, ``backend.app.db.models`` and
``backend/migrations/versions/0001_add_rbac_and_subscription_columns.py``
are the authority for the schema figures, and the filesystem is the
authority for whether a link resolves. Each is read here rather than
restated.

Claims that are matters of judgement rather than fact -- whether a
rationale is convincing, whether prose is clear -- are deliberately not
covered. Only what can be checked without inventing a rule is.
"""

import re
import subprocess
from pathlib import Path

import pytest
import yaml
from alembic.config import Config
from alembic.script import ScriptDirectory
from conftest import REPO_ROOT
from sqlalchemy import UniqueConstraint

from backend.app.core.config import ENV_FILE_VARIABLE
from backend.app.db.models import Base
from backend.tests.support import ALEMBIC_INI

#: Project readme.
README = REPO_ROOT / "README.md"

#: Vulnerability disclosure policy.
SECURITY_POLICY = REPO_ROOT / "SECURITY.md"

#: Workflow that verifies a change, the authority for what is automated.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Documents whose published contacts and links are checked.
DOCUMENTS = (README, SECURITY_POLICY)

#: Strings that name nobody. A document carrying one of these invites a
#: reader to send a vulnerability report into a mailbox that does not
#: exist, which is worse than publishing no address at all.
PLACEHOLDER_CONTACTS = (
    "your.email@example.com",
    "your-email@example.com",
    "Your Name",
    "your-username",
    "Your GitHub Profile",
    "youremail@example.com",
    "maintainer@example.com",
)

#: Matches a markdown inline link's target.
LINK_TARGET = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")

#: Matches a row of a markdown table, captured cell by cell.
TABLE_ROW = re.compile(r"^\|(.+)\|\s*$")

#: Matches the first backtick-quoted span in a table cell.
FIRST_CODE_SPAN = re.compile(r"`([^`]+)`")

#: Heading that introduces the verification gate table.
VERIFICATION_HEADING = "### Verification"

#: Bidirectional traceability matrix.
TRACEABILITY = REPO_ROOT / "docs" / "security" / "TRACEABILITY_MATRIX.md"

#: Heading that introduces the entry count reconciliation table.
ENTRY_COUNT_HEADING = "### 2.8 Entry count reconciliation"

#: The one reference-mode path delivery modified. Its history is what the
#: superseded "confirmed unmodified" claim contradicted.
MODIFIED_REFERENCE = "infrastructure/docker/Dockerfile.frontend"

#: Sentence introducing the paths whose claim is verifiable by absence.
ABSENCE_CLAIM_HEADING = "**Verifiable by absence, precisely.**"

#: Matches a backtick-quoted repository path.
QUOTED_PATH = re.compile(r"`([A-Za-z0-9_./() -]+\.[A-Za-z0-9]+)`")

#: Matches a bold or plain integer in a table cell.
CELL_NUMBER = re.compile(r"\*{0,2}(\d+)\*{0,2}")

#: Tokens a command is stripped of before it is looked for in the
#: workflow, because they express how a human runs it rather than what is
#: run.
IGNORED_COMMAND_TOKENS = ("python -m ", "-q", "--pretty")

#: The README's claim about how the gate's jobs are ordered. The workflow
#: is the authority for it, and it is read from the flattened document
#: because the sentence wraps.
NO_JOB_DEPENDENCY_CLAIM = "**None of them declares a dependency on another**"

#: Matches a workflow step name the README quotes, as ``step "name"``.
QUOTED_STEP = re.compile(r'step "([^"]+)"')

#: Revision that owns every schema construct the matrix's section 5 maps.
SCHEMA_REVISION = "0001"

#: Revision identifier of the login-throttling slot table. It creates the
#: second table this work introduces, so the columns it carries belong to
#: the introduced set alongside revision 0001's. Deriving that set from
#: 0001 alone counted this table's columns as pre-existing, which is what
#: this constant exists to prevent recurring at a sixth revision.
SLOT_REVISION = "0005"

#: Sentence that opens the matrix's measured schema totals.
SCHEMA_TOTALS_MARKER = "**Totals, measured.**"

#: Sentence that opens the provenance split of those totals.
SCHEMA_PROVENANCE_MARKER = "**Provenance of those 48 columns, measured.**"

#: Sentence that repeats both in the matrix's completeness summary.
SCHEMA_SUMMARY_MARKER = "**Schema constructs, both directions.**"

#: Heading of the enumeration of the columns this work introduces.
INTRODUCED_COLUMNS_HEADING = "### 5.2 Every column this work introduces"

#: Heading of the exhaustive column enumeration.
EVERY_COLUMN_HEADING = "### 5.8 Every column, enumerated"

#: Wording that marks a column as introduced rather than pre-existing in
#: the exhaustive enumeration.
INTRODUCED_MARKERS = ("Added by", "Introduced with the table by")


def _read(path):
    """Returns a document's text."""
    return path.read_text(encoding="utf-8")


def _section(text, heading):
    """Returns the lines of one section, heading excluded.

    A section ends at the next heading of the same or a higher level, so
    a table is read out of the section that introduces it rather than out
    of the whole document.
    """
    lines = text.splitlines()
    start = lines.index(heading)
    level = len(heading) - len(heading.lstrip("#"))
    for offset, line in enumerate(lines[start + 1:], start=start + 1):
        if line.startswith("#"):
            if len(line) - len(line.lstrip("#")) <= level:
                return lines[start + 1:offset]
    return lines[start + 1:]


def _table_rows(lines):
    """Returns each table row in ``lines`` as a list of cells."""
    rows = []
    for line in lines:
        matched = TABLE_ROW.match(line)
        if matched is None:
            continue
        cells = [cell.strip() for cell in matched.group(1).split("|")]
        if all(set(cell) <= set("-: ") for cell in cells):
            continue
        rows.append(cells)
    return rows[1:] if rows else rows


def _job_shell(document, jobs):
    """Returns the shell the named jobs run, comments dropped.

    Prose can contain any command name, so a claim about what a job
    automates has to rest on what that job executes.
    """
    lines = []
    for job in jobs:
        for step in document["jobs"][job].get("steps", []):
            if "run" not in step:
                continue
            lines.extend(
                line
                for line in step["run"].splitlines()
                if not line.lstrip().startswith("#")
            )
    return " ".join(" ".join(lines).split())


def _workflow_shell():
    """Returns every shell line the verification workflow runs.

    Comment lines are dropped: prose can contain any command name, and a
    claim about what is automated has to rest on what is executed.
    """
    document = yaml.safe_load(_read(CI_WORKFLOW))
    blocks = []
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            if "run" not in step:
                continue
            blocks.extend(
                line for line in step["run"].splitlines()
                if not line.lstrip().startswith("#")
            )
    return "\n".join(blocks)


def _commands(cell):
    """Returns the runnable segments of a documented command.

    A cell may chain several commands, and may start in a directory the
    workflow reaches another way, so it is split on the chaining operator
    and any directory change is dropped.
    """
    span = FIRST_CODE_SPAN.search(cell)
    if span is None:
        return []
    segments = []
    for segment in span.group(1).split("&&"):
        trimmed = segment.strip()
        if not trimmed or trimmed.startswith("cd "):
            continue
        for token in IGNORED_COMMAND_TOKENS:
            trimmed = trimmed.replace(token, " ")
        segments.append(" ".join(trimmed.split()))
    return segments


def _number(cell):
    """Returns the integer a table cell holds, or ``None``."""
    matched = CELL_NUMBER.fullmatch(cell.strip())
    return int(matched.group(1)) if matched else None


def _labelled_number(body, label):
    """Returns the integer on the table row carrying ``label``."""
    for line in body.splitlines():
        if label in line and line.startswith("|"):
            for cell in line.split("|"):
                value = _number(cell)
                if value is not None:
                    return value
    return None


def _absence_claims(body):
    """Returns the paths claimed verifiable by absence from history."""
    lines = body.splitlines()
    for index, line in enumerate(lines):
        if line.startswith(ABSENCE_CLAIM_HEADING):
            break
    else:
        return set()
    collected = set()
    for line in lines[index:]:
        if not line.strip():
            break
        collected.update(QUOTED_PATH.findall(line))
    return {path for path in collected if (REPO_ROOT / path).exists()}


def _flat(text):
    """Returns ``text`` with every run of whitespace reduced to a space.

    A claim in prose wraps across lines, so it is read from a flattened
    copy rather than line by line.
    """
    return re.sub(r"\s+", " ", text)


def _paragraph(text, marker):
    """Returns the flattened paragraph that begins with ``marker``."""
    for block in text.split("\n\n"):
        if marker in block:
            return _flat(block)
    return ""


def _stated(paragraph, pattern):
    """Returns the integers ``pattern`` captures in ``paragraph``."""
    matched = re.search(pattern, paragraph)
    assert matched is not None, (pattern, paragraph)
    return tuple(int(group) for group in matched.groups())


def _revision_module(revision):
    """Returns the loaded module of one revision in this repository."""
    return ScriptDirectory.from_config(
        Config(str(ALEMBIC_INI))
    ).get_revision(revision).module


def _appended_columns():
    """Returns the columns revision 0001 adds to a pre-existing table.

    Read from the revision, which is the authority for what it appends:
    these are the columns its legacy-baseline path passes to
    ``op.add_column`` and its empty-database path folds into a
    ``create_table``.
    """
    module = _revision_module(SCHEMA_REVISION)
    return ["users.%s" % column.name
            for column in module._users_added_columns()] + [
        "subscriptions.%s" % column.name
        for column in module._subscriptions_added_columns()
    ]


def _carried_columns():
    """Returns the columns of the table revision 0001 creates outright."""
    module = _revision_module(SCHEMA_REVISION)
    table = Base.metadata.tables[module.WEBHOOK_EVENTS]
    return ["%s.%s" % (table.name, column.name) for column in table.columns]


def _slot_columns():
    """Returns the columns of the table revision 0005 creates outright."""
    module = _revision_module(SLOT_REVISION)
    table = Base.metadata.tables[module.TABLE_NAME]
    return ["%s.%s" % (table.name, column.name) for column in table.columns]


def _introduced_columns():
    """Returns every column this work introduces, from the revisions.

    Two revisions add columns: 0001 appends to two pre-existing tables and
    creates one table outright, and 0005 creates one table outright. A
    column is introduced when a revision in this repository brings it,
    which is what a reviewer asking how much of the schema this work is
    answerable for is counting.
    """
    return _appended_columns() + _carried_columns() + _slot_columns()


def _every_column():
    """Returns every mapped column as ``table.column``."""
    return [
        "%s.%s" % (name, column.name)
        for name, table in Base.metadata.tables.items()
        for column in table.columns
    ]


def _uniqueness_names():
    """Returns one entry per distinct uniqueness the models declare.

    A column declared ``unique=True`` also produces an unnamed constraint
    object over that one column, so counting both would count one
    uniqueness twice.
    """
    found = []
    for name, table in Base.metadata.tables.items():
        for column in table.columns:
            if column.unique:
                found.append("%s.%s" % (name, column.name))
        for constraint in table.constraints:
            if isinstance(constraint, UniqueConstraint) and constraint.name:
                found.append(constraint.name)
    return found


def _commit_count(path):
    """Returns how many commits touched ``path``, following renames."""
    completed = subprocess.run(
        ["git", "log", "--follow", "--oneline", "--", path],
        cwd=str(REPO_ROOT), capture_output=True, text=True,
    )
    assert completed.returncode == 0, completed.stderr
    return len([line for line in completed.stdout.splitlines() if line])


class TestNoPublishedContactIsAPlaceholder:
    """Cases over the addresses these documents publish."""

    @pytest.mark.parametrize(
        "document", DOCUMENTS, ids=lambda path: path.name,
    )
    @pytest.mark.parametrize("placeholder", PLACEHOLDER_CONTACTS)
    def test_the_document_carries_no_placeholder(self, document, placeholder):
        """Asserts no document names a contact that reaches nobody."""
        assert placeholder not in _read(document), (
            document.name, placeholder,
        )

    def test_the_policy_names_a_channel_that_needs_no_address(self):
        """Asserts a working reporting route is published.

        Removing a placeholder is only an improvement if something
        usable is left, so the case checks that the private reporting
        route is still described rather than that the file is merely
        free of placeholders.
        """
        body = _read(SECURITY_POLICY)
        assert "Report a vulnerability" in body
        assert "private vulnerability reporting" in body.lower()

    def test_neither_document_invites_a_public_disclosure(self):
        """Asserts both documents warn against reporting in the open."""
        for document in DOCUMENTS:
            body = _read(document).lower()
            assert "do not report" in body or "do not open a public" in body, (
                document.name
            )


class TestEveryLinkResolves:
    """Cases over the relative links these documents carry."""

    @pytest.mark.parametrize(
        "document", DOCUMENTS, ids=lambda path: path.name,
    )
    def test_every_relative_link_names_something_that_exists(self, document):
        """Asserts no link points at a path the repository lacks.

        Absolute links and in-page anchors are skipped: the first needs
        the network to check and the second names no path.
        """
        missing = []
        for target in LINK_TARGET.findall(_read(document)):
            if target.startswith(("http://", "https://", "#", "mailto:")):
                continue
            path = REPO_ROOT / Path(target.split("#", 1)[0])
            if not path.exists():
                missing.append(target)
        assert missing == [], (document.name, missing)


class TestTheAutomationClaimIsTrue:
    """Cases over which documented gates continuous integration runs."""

    def test_the_verification_table_is_present_and_populated(self):
        """Asserts the table the other cases read actually exists."""
        rows = _table_rows(_section(_read(README), VERIFICATION_HEADING))
        assert len(rows) >= 8, len(rows)

    def test_every_documented_gate_runs_in_the_workflow(self):
        """Asserts nothing in the table is claimed as automated falsely.

        The table's third column states what fails when a command fails.
        A row that names a continuous-integration job is claiming
        automation, and that claim is checked against the named job's own
        shell rather than against a second list of it. A row that says
        plainly that nothing but the reader runs the command claims
        nothing and is required only not to name a job.

        The distinction is the point of the column: the documented form of
        a gate is the one a reader runs by hand, and the pipeline may run
        a stricter or differently scoped form of it -- the audits as
        ``--strict`` with each accepted advisory suppressed by identifier,
        the linter from inside ``backend/``. So what is asserted for an
        automated row is that the job exists and that it invokes the
        command's program, which is what makes the attribution checkable
        without requiring the two spellings to be identical.
        """
        document = yaml.safe_load(_read(CI_WORKFLOW))
        rows = _table_rows(_section(_read(README), VERIFICATION_HEADING))
        assert rows, "no verification table found"
        wrong = []
        for cells in rows:
            if len(cells) < 3:
                continue
            enforced = cells[2]
            named = [
                job for job in document["jobs"] if "`%s`" % job in enforced
            ]
            if not named:
                #: A row naming no job claims no automation, and the column
                #: is required to say so rather than leaving it to be read
                #: out of the absence of a name.
                if "Manual" not in enforced:
                    wrong.append(("names no job and no reader", cells[0][:60]))
                continue
            if "Partly" in enforced:
                #: The row states its own limit, so what is asserted is that
                #: the limit is stated rather than that the whole command
                #: runs. The prose names what the job does not do.
                if "not" not in enforced:
                    wrong.append(("partly automated, limit unstated", named))
                continue
            shell = _job_shell(document, named)
            for command in _commands(cells[0]):
                program = command.split()[0]
                if program not in shell:
                    wrong.append((program, named))
        assert wrong == [], wrong

    def test_every_job_the_readme_names_exists(self):
        """Asserts the README's job table matches the workflow's jobs."""
        document = yaml.safe_load(_read(CI_WORKFLOW))
        declared = set(document["jobs"])
        named = set()
        for line in _read(README).splitlines():
            if not line.startswith("| `"):
                continue
            span = FIRST_CODE_SPAN.search(line)
            if span is not None and span.group(1) in declared:
                named.add(span.group(1))
        assert named == declared, sorted(declared - named)

    def test_every_step_the_readme_quotes_exists_in_the_job_it_names(self):
        """Asserts a quoted step name belongs to a job the same row names.

        A row that names the wrong job still passes a command-level check,
        because several jobs run the same program. The step name is what
        makes the attribution specific, so it is resolved against the steps
        of the jobs that row names.
        """
        document = yaml.safe_load(_read(CI_WORKFLOW))
        steps_by_job = dict(
            (
                name,
                set(
                    str(step.get("name"))
                    for step in job.get("steps") or []
                    if step.get("name")
                ),
            )
            for name, job in document["jobs"].items()
        )
        wrong = []
        for cells in _table_rows(
            _section(_read(README), VERIFICATION_HEADING)
        ):
            if len(cells) != 3:
                continue
            named = [
                job for job in steps_by_job
                if "`%s`" % job in cells[2]
            ]
            for quoted in QUOTED_STEP.findall(cells[2]):
                if not any(quoted in steps_by_job[job] for job in named):
                    wrong.append((quoted, named))
        assert wrong == [], wrong

    def test_the_readme_describes_the_job_dependencies_that_exist(self):
        """Asserts what the README says about job ordering is what runs.

        A reader plans around this claim: a job described as waiting on
        another is a job whose gates the reader believes will not run when
        that other fails, and a job described as independent is one the
        reader expects to report on its own.
        """
        document = yaml.safe_load(_read(CI_WORKFLOW))
        dependent = dict(
            (name, job["needs"])
            for name, job in document["jobs"].items()
            if job.get("needs")
        )
        claim = _flat(_read(README))

        assert dependent == {}, dependent
        assert NO_JOB_DEPENDENCY_CLAIM in claim
        assert "needs: backend" not in claim


class TestTheTraceabilityCountsReconcile:
    """Cases over the arithmetic the traceability matrix publishes.

    The matrix states counts and then claims completeness on the strength
    of them, so a count that does not add up undermines the claim it
    supports. Nothing checked the arithmetic before, which is how a row
    recording a modified file as unmodified survived.
    """

    def test_the_group_subtotals_add_to_the_stated_total(self):
        """Asserts the reconciliation table's rows sum to its total."""
        rows = [
            cells for cells in _table_rows(
                _section(_read(TRACEABILITY), ENTRY_COUNT_HEADING),
            )
            if len(cells) == 6
        ]
        assert rows, "no reconciliation table found"
        total = None
        groups = []
        for cells in rows:
            numbers = [_number(cell) for cell in cells[1:]]
            if any(number is None for number in numbers):
                continue
            if "total" in cells[0].lower():
                total = numbers
            else:
                groups.append(numbers)
        assert total is not None, "no total row found"
        assert groups, "no group rows found"
        for column, expected in enumerate(total[:-1]):
            assert sum(row[column] for row in groups) == expected, column
        assert sum(row[-1] for row in groups) == total[-1]
        assert sum(total[:-1]) == total[-1], total

    def test_the_delivered_count_exceeds_the_planned_count_by_one(self):
        """Asserts the plan-versus-delivery table is self-consistent.

        The distinction the table draws is the correction it exists to
        record: one path the plan assigns reference mode was modified, so
        delivery touched one path more than the plan's changed set holds.
        """
        body = _read(TRACEABILITY)
        planned = _labelled_number(body, "Plan changed paths")
        delivered = _labelled_number(body, "Delivered changed paths")
        unmodified = _labelled_number(body, "delivered unmodified")
        modified = _labelled_number(body, "modified in delivery")
        references = _labelled_number(body, "Plan reference paths")
        assert None not in (
            planned, delivered, unmodified, modified, references,
        ), (planned, delivered, unmodified, modified, references)
        assert unmodified + modified == references
        assert planned + modified == delivered

    def test_each_path_claimed_unmodified_really_is(self):
        """Asserts the absence claim, path by path, against history.

        This is the case the matrix's own defect would have failed. Each
        path the document names as verifiable by absence is checked
        against the commits that touched it, and the one it names as
        modified is required to have been.
        """
        #: Nine paths are claimed verifiable by absence: the eight
        #: read-only authorities of section 2.7, and the contextual
        #: `backend/app/api/router.py` row section 2.1 renders. The ninth
        #: reference entry was modified and is asserted below to have been,
        #: so the plan's nine references plus the contextual row are
        #: partitioned with nothing unaccounted for.
        claimed = _absence_claims(_read(TRACEABILITY))
        assert len(claimed) == 9, sorted(claimed)
        for path in claimed:
            assert (REPO_ROOT / path).exists(), path
            assert _commit_count(path) == 1, (path, _commit_count(path))
        assert _commit_count(MODIFIED_REFERENCE) > 1, MODIFIED_REFERENCE

    def test_the_modified_reference_is_not_claimed_unmodified(self):
        """Asserts the corrected row no longer makes the false claim."""
        body = _read(TRACEABILITY)
        for line in body.splitlines():
            if MODIFIED_REFERENCE in line:
                assert "Confirmed unmodified" not in line, line


class TestTheSchemaFiguresMatchTheModels:
    """Cases over the schema figures the traceability matrix publishes.

    The matrix states its schema totals and its provenance split as
    measurements and then rests a completeness claim on them, so a figure
    that disagrees with the models withdraws the claim it supports. Each
    figure below is derived from ``Base.metadata`` and from revision
    ``0001`` and compared against the document, in both the section that
    states it and the summary that repeats it.
    """

    def test_the_stated_totals_are_the_measured_totals(self):
        """Asserts every count in the totals paragraph is the real one."""
        paragraph = _paragraph(_read(TRACEABILITY), SCHEMA_TOTALS_MARKER)
        columns = _every_column()

        assert _stated(paragraph, r"(\d+) tables") == (
            len(Base.metadata.tables),
        )
        assert _stated(
            paragraph,
            r"(\d+) columns, of which (\d+) are `NOT NULL` and (\d+) are"
            r" nullable",
        ) == (
            len(columns),
            len([
                column
                for table in Base.metadata.tables.values()
                for column in table.columns
                if not column.nullable
            ]),
            len([
                column
                for table in Base.metadata.tables.values()
                for column in table.columns
                if column.nullable
            ]),
        )
        assert _stated(paragraph, r"(\d+) server defaults") == (
            len([
                column
                for table in Base.metadata.tables.values()
                for column in table.columns
                if column.server_default is not None
            ]),
        )
        assert _stated(paragraph, r"(\d+) primary keys") == (
            len([
                table
                for table in Base.metadata.tables.values()
                if list(table.primary_key)
            ]),
        )
        assert _stated(paragraph, r"(\d+) foreign keys") == (
            len([
                key
                for table in Base.metadata.tables.values()
                for key in table.foreign_keys
            ]),
        )
        assert _stated(paragraph, r"(\d+) uniqueness") == (
            len(_uniqueness_names()),
        )
        assert _stated(
            paragraph, r"(\d+) ORM relationships across (\d+) reciprocal"
        ) == (
            sum(len(mapper.relationships) for mapper in Base.registry.mappers),
            sum(
                len(mapper.relationships) for mapper in Base.registry.mappers
            ) // 2,
        )

    def test_the_stated_provenance_split_is_the_measured_one(self):
        """Asserts the introduced and pre-existing counts are the real ones.

        The split is what a reviewer of a migration reads first: how much
        of the schema this work is answerable for. The four figures are the
        introduced total, the pre-existing total, how many of the
        introduced ones are appended to a table that already existed, and
        how many arrive with each of the two tables the revisions create.
        """
        paragraph = _paragraph(_read(TRACEABILITY), SCHEMA_PROVENANCE_MARKER)
        appended = _appended_columns()
        carried = _carried_columns()
        slots = _slot_columns()
        introduced = len(_introduced_columns())

        assert _stated(
            paragraph, r"(\d+) are introduced by this work and (\d+) precede"
        ) == (introduced, len(_every_column()) - introduced)
        assert _stated(paragraph, r"The (\d+) divide by how they arrive") == (
            introduced,
        )
        assert _stated(paragraph, r"(\d+) are appended") == (len(appended),)
        assert _stated(
            paragraph, r"(\d+) on `users` and (\d+) on `subscriptions`"
        ) == (
            len([name for name in appended if name.startswith("users.")]),
            len([
                name for name in appended
                if name.startswith("subscriptions.")
            ]),
        )
        assert _stated(paragraph, r"(\d+) are carried by") == (len(carried),)
        assert _stated(
            paragraph, r"(\d+) are carried by\s+`login_attempt_slots`"
        ) == (len(slots),)

    def test_the_introduced_columns_are_enumerated_exactly(self):
        """Asserts section 5.2 lists every introduced column and no other."""
        rows = _table_rows(
            _section(_read(TRACEABILITY), INTRODUCED_COLUMNS_HEADING)
        )
        listed = []
        for cells in rows:
            matched = FIRST_CODE_SPAN.search(cells[1])
            assert matched is not None, cells
            listed.append(matched.group(1))
        expected = _introduced_columns()

        assert len(listed) == len(set(listed)), listed
        assert sorted(listed) == sorted(expected), (listed, expected)

    def test_every_column_is_enumerated_with_its_provenance(self):
        """Asserts section 5.8 lists every column and marks the right ones.

        The enumeration is where a pre-existing column is individually
        accounted for, so a column missing from it, or one whose
        provenance reads the wrong way round, is what this catches.
        """
        rows = _table_rows(
            _section(_read(TRACEABILITY), EVERY_COLUMN_HEADING)
        )
        introduced = set(_introduced_columns())
        listed = []
        for cells in rows:
            table = FIRST_CODE_SPAN.search(cells[1])
            column = FIRST_CODE_SPAN.search(cells[2])
            assert table is not None and column is not None, cells
            name = "%s.%s" % (table.group(1), column.group(1))
            listed.append(name)
            marked = any(
                marker in cells[-1] for marker in INTRODUCED_MARKERS
            )
            assert marked is (name in introduced), (name, cells[-1])

        assert len(listed) == len(set(listed)), listed
        assert sorted(listed) == sorted(_every_column()), listed

    def test_the_summary_repeats_the_measured_figures(self):
        """Asserts the completeness summary states the same figures.

        The summary is the paragraph a reader who skips section 5 reads,
        so it is checked against the models directly rather than against
        the section it summarises.
        """
        paragraph = _paragraph(_read(TRACEABILITY), SCHEMA_SUMMARY_MARKER)
        columns = _every_column()
        introduced = len(_introduced_columns())

        assert _stated(paragraph, r"\*\*(\d+)\*\* tables") == (
            len(Base.metadata.tables),
        )
        assert _stated(paragraph, r"\*\*(\d+)\*\* introduced columns") == (
            introduced,
        )
        assert _stated(paragraph, r"all \*\*(\d+)\*\* columns") == (
            len(columns),
        )
        assert _stated(
            paragraph, r"\*\*(\d+)\*\* `NOT NULL` plus \*\*(\d+)\*\* nullable"
        ) == (
            len([
                column
                for table in Base.metadata.tables.values()
                for column in table.columns
                if not column.nullable
            ]),
            len([
                column
                for table in Base.metadata.tables.values()
                for column in table.columns
                if column.nullable
            ]),
        )
        assert _stated(
            paragraph, r"so the \*\*(\d+)\*\* that precede this work"
        ) == (len(columns) - introduced,)


class TestTheConfigurationClaimMatches:
    """Cases over how the README says configuration is loaded."""

    def test_the_readme_does_not_claim_a_working_directory_default(self):
        """Asserts the superseded literal claim is gone.

        The settings class resolves an absolute path under the
        repository root, so describing the default as a bare relative
        filename tells a reader the wrong thing about running a command
        from a subdirectory.
        """
        assert 'env_file = ".env"' not in _read(README)

    def test_the_readme_documents_the_override_variable(self):
        """Asserts the variable that redirects the file is described."""
        assert ENV_FILE_VARIABLE in _read(README)

    def test_the_readme_describes_the_repository_root_default(self):
        """Asserts the default location is described as the root."""
        body = _read(README).lower()
        assert "repository root" in body
