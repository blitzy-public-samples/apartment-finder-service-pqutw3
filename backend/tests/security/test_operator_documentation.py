"""Checks over the instructions this repository gives an operator.

``README.md``, ``SECURITY.md`` and
``docs/security/CREDENTIAL_ROTATION.md`` are executed by people, and a
command in one of them is as much a delivered artifact as a function is.
Three classes of defect are asserted against here, because each one was
found in these documents rather than imagined:

* **A documented command that destroys something.** A copy that
  overwrites a secret-bearing file, or a migration sequence that ends
  with the authorization revisions removed. Every step exits zero while
  doing it, so nothing but reading the sequence catches it.
* **A documented command that discloses a secret.** A signing key sent
  to stdout is retained by scrollback, shell history, a CI job log and
  any transcript of the session.
* **A documented fact that disagrees with the tree, or with another
  document.** An inventory that counts four pin sites where there are
  five, or a runbook that calls a credential compromised when it was
  never exposed.
* **A document that overstates how far the work has got.** The
  executive deck is covered here for the same reason: it is read by
  people who will read nothing else, so a finding it calls closed is a
  finding the organisation believes is in production.

Where a command can be run without contacting anything, it is extracted
from the document and executed, so that what is asserted is the text an
operator would actually paste. Design rationale is recorded in
``docs/security/DECISION_LOG.md``.
"""

import io
import os
import re
import shutil
import subprocess

import pytest
from conftest import REPO_ROOT

from backend.tests.support import REVISION_COUNT, REVISION_IDS

#: Documents under test.
README = REPO_ROOT / "README.md"
SECURITY_POLICY = REPO_ROOT / "SECURITY.md"
ROTATION_RUNBOOK = (
    REPO_ROOT / "docs" / "security" / "CREDENTIAL_ROTATION.md"
)
RESIDUAL_RISK_REGISTER = (
    REPO_ROOT / "docs" / "security" / "RESIDUAL_RISK.md"
)
DECISION_LOG = REPO_ROOT / "docs" / "security" / "DECISION_LOG.md"
TRACEABILITY_MATRIX = (
    REPO_ROOT / "docs" / "security" / "TRACEABILITY_MATRIX.md"
)
CRITICAL_DECISIONS = (
    REPO_ROOT / "docs" / "review" / "CRITICAL_DECISIONS.md"
)

#: Revision the tree stood at before this remediation began. Both Rule 1
#: artifacts cite it, and the delivered set is measured against it.
BASELINE_REVISION = "a26f7fb"

#: Rows the reverse index carries across its three tables: the 69 rows it
#: renders for the plan's 68 entries, the 26 delivered beyond the plan, and
#: the 61 delivered by later rounds. 130 of the 156 are paths in the
#: delivered change set; of the remaining 26, nine are read-only references
#: confirmed unmodified and seventeen were withdrawn -- sixteen by the
#: manifest consolidation and one by the provider-pinning revert -- which is
#: the arithmetic section 2.10 publishes.
MATRIX_REVERSE_ROWS = 157

#: Paths produced while verifying, never delivered, and removed
#: before commit. ``blitzy/`` is where the browser-validation
#: tooling writes its screenshots and recordings; the rest are
#: scratch files a validation command wrote.
BYPRODUCT_PREFIXES = ("blitzy_adhoc", "blitzy/")
BYPRODUCT_SUFFIXES = (".log", ".err", ".pid")

#: Status ``git status --porcelain`` reports for a path it does not
#: track. Such a path is not part of the delivered change.
UNTRACKED_STATUS = "??"

#: Committed template the bootstrap copies from.
ENVIRONMENT_TEMPLATE = REPO_ROOT / ".env.example"

#: Every site the CPython 3.9 pin is load-bearing at. The fifth is a
#: language construct rather than a version declaration, and omitting it
#: understates the constraint.
PIN_SITES = (
    "infrastructure/docker/Dockerfile.backend",
    ".github/workflows/ci.yml",
    "infrastructure/terraform/main.tf",
    "scripts/deploy.sh",
    "backend/app/tasks/listing_updater.py",
)

#: Construct that pins the interpreter in code.
CODE_LEVEL_PIN = "@asyncio.coroutine"

#: Text identifying the documented command that starts the application.
ASGI_APP_MARKER = "uvicorn backend.app.main:app"

#: Flag that leaves the peer address of the connection in the ASGI scope.
NO_PROXY_HEADERS_FLAG = "--no-proxy-headers"

#: Flag that names the addresses whose forwarded header is honoured, which
#: an operator needing the server to resolve the address reaches for
#: instead.
FORWARDED_ALLOW_FLAG = "--forwarded-allow-ips"

#: Setting that decides the address a rate limit is counted against.
HOP_SETTING = "TRUSTED_PROXY_HOPS"


def _delivered_revision_head() -> str:
    """Returns the head of the delivered Alembic chain.

    The chain is read from the revision files rather than fixed here, so
    a revision added later cannot leave a documented head standing
    without this assertion noticing.
    """
    parents = {}
    versions = REPO_ROOT / "backend" / "migrations" / "versions"
    for path in sorted(versions.glob("[0-9]*.py")):
        text = path.read_text(encoding="utf-8")
        identifier = re.search(
            r'^revision = "([^"]+)"', text, re.MULTILINE
        )
        parent = re.search(
            r'^down_revision = (?:"([^"]+)"|None)', text, re.MULTILINE
        )
        assert identifier is not None, path
        assert parent is not None, path
        parents[identifier.group(1)] = parent.group(1)

    assert parents, "the migrations directory holds no revision"
    revised = set(parent for parent in parents.values() if parent)
    heads = sorted(set(parents) - revised)
    assert len(heads) == 1, heads
    return heads[0]


#: Head Alembic revision. A documented reversibility check has to end
#: here, not some number of downgrades below it.
HEAD_REVISION = _delivered_revision_head()

#: Number of revisions the delivered chain carries, read from the chain. A
#: documented reversal is one step per revision, so a count stated in the
#: readme is checked against this rather than against a written figure.
REVERSAL_STEPS = REVISION_COUNT

#: Seconds an extracted command is allowed.
EXECUTION_TIMEOUT_SECONDS = 60


def _text(path):
    """Returns one document as text with newlines normalised."""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _flattened(path):
    """Returns one document as a single whitespace-collapsed line.

    Prose in these documents is hard-wrapped, so a sentence asserted
    against would otherwise have to be matched around a line break.
    """
    return " ".join(_text(path).split())


def _shell_blocks(path):
    """Returns every fenced bash block in one document."""
    return re.findall(r"```bash\n(.*?)```", _text(path), re.S)


def _block_containing(path, needle):
    """Returns the one bash block holding ``needle``."""
    found = [b for b in _shell_blocks(path) if needle in b]
    assert len(found) == 1, (
        str(path) + " has " + str(len(found)) + " blocks with " + needle
    )
    return found[0]


def _bash():
    """Returns a bash interpreter, or skips the case."""
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
    pytest.skip("no bash interpreter is available on this host")


def _run(script, directory):
    """Runs one extracted block in a scratch directory."""
    return subprocess.run(
        [_bash(), "-c", script],
        cwd=str(directory),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=EXECUTION_TIMEOUT_SECONDS,
        universal_newlines=True,
    )


@pytest.fixture()
def workspace(tmp_path):
    """A scratch directory holding only the committed template."""
    shutil.copy(
        str(ENVIRONMENT_TEMPLATE), str(tmp_path / ".env.example")
    )
    return tmp_path


# --- The bootstrap must not overwrite a secret-bearing file ----------------


def test_the_readme_bootstrap_is_not_an_unguarded_copy():
    """No document tells an operator to overwrite ``.env``.

    ``cp .env.example .env`` replaces a file holding real secrets and
    exits zero, so the failure is silent and total.
    """
    for path in (README, SECURITY_POLICY, ROTATION_RUNBOOK):
        for block in _shell_blocks(path):
            for line in block.split("\n"):
                stripped = line.strip()
                assert stripped != "cp .env.example .env", str(path)


def test_the_readme_bootstrap_guards_the_copy_and_restricts_the_mode():
    """The documented copy is conditional and runs under a umask."""
    block = _block_containing(README, "leaving it untouched")

    assert "if [ -e .env ]" in block
    assert "umask 077" in block
    assert "cp .env.example .env" in block


def test_the_documented_bootstrap_creates_the_file_when_absent(
    workspace,
):
    """Running the documented block produces ``.env`` from the template."""
    block = _block_containing(README, "leaving it untouched")

    result = _run(block, workspace)

    assert result.returncode == 0, result.stderr
    created = workspace / ".env"
    assert created.is_file()
    assert created.read_text(encoding="utf-8") == (
        ENVIRONMENT_TEMPLATE.read_text(encoding="utf-8")
    )


def test_the_documented_bootstrap_refuses_to_replace_an_existing_file(
    workspace,
):
    """A second run leaves the file byte-identical and says so."""
    block = _block_containing(README, "leaving it untouched")
    existing = workspace / ".env"
    existing.write_text("SECRET_KEY=a-real-key-already-here\n",
                        encoding="utf-8")
    before = existing.read_text(encoding="utf-8")

    result = _run(block, workspace)

    assert result.returncode == 0
    assert existing.read_text(encoding="utf-8") == before
    assert "already exists" in result.stderr


def test_the_readme_names_the_setup_script_as_the_safe_path():
    """The script is offered first, and its behaviour is stated."""
    flat = _flattened(README)

    assert "scripts/setup_dev_environment.sh" in flat
    assert "keeps an existing `.env`" in flat


# --- A generated secret is never displayed --------------------------------


@pytest.mark.parametrize(
    "path", [README, ROTATION_RUNBOOK, SECURITY_POLICY]
)
def test_no_document_prints_a_generated_secret(path):
    """No documented command sends a fresh key to stdout.

    Both documents previously did: ``print(secrets.token_urlsafe(48))``
    in the README and again in the runbook's rotation step.
    """
    text = _text(path)

    assert "print(secrets.token_urlsafe" not in text
    assert "print(secrets." not in text

    for block in _shell_blocks(path):
        for line in block.split("\n"):
            if "openssl rand" not in line:
                continue
            assert ">" in line or "|" in line, line


@pytest.mark.parametrize("path", [README, ROTATION_RUNBOOK])
def test_every_key_generation_block_sends_the_value_to_a_destination(
    path,
):
    """A generated key is written somewhere protected, not shown.

    "Somewhere" is any of three delivered forms: an in-language write to
    the environment file, a shell redirect into a file created under a
    restrictive umask, or a pipe into the managed secret store. What none
    of them may do is let the value reach a terminal.
    """
    blocks = [
        b for b in _shell_blocks(path) if "token_urlsafe" in b
    ]

    assert blocks, str(path) + " documents no key generation"
    for block in blocks:
        # The value is protected in transit or at rest.
        assert "umask 077" in block or "--data-file=-" in block, block

        # And it lands in a destination rather than on the screen.
        destinations = (
            "write_text(",
            "--data-file=-",
            "> \"${",
            "> $",
        )
        assert any(form in block for form in destinations), block

        # Nothing in the block displays it.
        for shown in ("print(", "echo $", 'echo "$', "cat "):
            assert shown not in block, block


def test_the_readme_key_generation_writes_into_the_file_silently(
    workspace,
):
    """Running the documented block rewrites the key and prints nothing."""
    shutil.copy(str(ENVIRONMENT_TEMPLATE), str(workspace / ".env"))
    before = (workspace / ".env").read_text(encoding="utf-8")
    block = _block_containing(README, "token_urlsafe")

    result = _run(block, workspace)

    assert result.returncode == 0, result.stderr
    assert result.stdout == ""
    assert result.stderr == ""

    after = (workspace / ".env").read_text(encoding="utf-8")
    generated = re.search(r"(?m)^SECRET_KEY=(.*)$", after).group(1)

    assert len(generated) >= 32
    assert generated not in result.stdout + result.stderr
    assert "CHANGE_ME_generate_a_real_key" not in after
    assert len(after.split("\n")) == len(before.split("\n"))

    changed = [
        old
        for old, new in zip(before.split("\n"), after.split("\n"))
        if old != new
    ]
    assert len(changed) == 1
    assert changed[0].startswith("SECRET_KEY=")


def test_the_readme_verification_reports_a_property_not_the_value(
    workspace,
):
    """The confirmation step prints a length, never the key."""
    shutil.copy(str(ENVIRONMENT_TEMPLATE), str(workspace / ".env"))
    _run(_block_containing(README, "token_urlsafe"), workspace)
    generated = re.search(
        r"(?m)^SECRET_KEY=(.*)$",
        (workspace / ".env").read_text(encoding="utf-8"),
    ).group(1)

    result = _run(
        _block_containing(README, "characters written").split("\n")[0],
        workspace,
    )

    assert result.returncode == 0, result.stderr
    assert "characters written" in result.stdout
    assert generated not in result.stdout


def test_the_runbook_rotation_step_disables_tracing_and_verifies_by_name():
    """Rotation streams the key out of sight and checks the version."""
    text = _text(ROTATION_RUNBOOK)
    flat = _flattened(ROTATION_RUNBOOK)

    assert "set +x" in text
    assert "gcloud secrets versions add SECRET_KEY --data-file=-" in text
    assert "gcloud secrets versions list SECRET_KEY" in text
    assert "Verify by identifier, not by value" in flat


def test_the_runbook_names_the_secret_terraform_actually_provisions():
    """The rotation command targets a secret that exists.

    Terraform names each secret after the setting that consumes it, so a
    runbook naming anything else would fail at the keyboard.
    """
    terraform = _text(
        REPO_ROOT / "infrastructure" / "terraform" / "main.tf"
    )

    assert 'secret_id = "SECRET_KEY"' in terraform
    assert "versions add SECRET_KEY" in _text(ROTATION_RUNBOOK)


# --- The documented migration check is not destructive --------------------


def test_the_documented_reversibility_check_ends_at_head():
    """The sequence finishes upgraded, and says which revision that is.

    A sequence that ends on a reversal leaves the RBAC column and the
    administrator seed removed while every command exits zero, so the row is
    read for the order of its calls as well as their presence. The number of
    reversals it states is compared against the delivered chain, and every
    revision the reader steps through is named, so a chain that grows makes
    this row fail rather than quietly under-count.
    """
    flat = _flattened(README)
    row = [
        line
        for line in _text(README).split("\n")
        if line.startswith("| Reversibility")
    ]

    assert len(row) == 1
    assert row[0].rstrip().endswith("|")
    assert row[0].index("alembic downgrade -1") < row[0].rindex(
        "alembic upgrade head"
    )
    assert "alembic current" in row[0]
    assert HEAD_REVISION + " (head)" in row[0]
    assert "disposable database" in row[0]
    assert "per revision in the chain" in row[0]
    assert "(%d today" % REVERSAL_STEPS in row[0]
    for revision in REVISION_IDS:
        assert revision in row[0], revision
    assert "base" in row[0]
    assert "downgrade -1` twice |" not in flat


def test_the_readme_warns_that_the_downgrades_are_destructive():
    """The cost of the reversals is stated, with their number, not implied."""
    flat = _flattened(README)

    assert "must not be run against a database you intend to keep" in flat
    assert "`role` column" in flat
    assert "seeds the single administrator" in flat
    assert "exits 0 while doing it" in flat
    assert "per revision in the chain, %d today" % REVERSAL_STEPS in flat


# --- Facts must agree with the tree and with each other -------------------


@pytest.mark.parametrize("site", PIN_SITES)
def test_the_policy_pin_inventory_names_every_site(site):
    """All five pin sites appear in the disclosure policy.

    It listed four and omitted the code-level site, which is the one
    that makes the pin self-enforcing.
    """
    section = _text(SECURITY_POLICY).split("### Runtime baseline", 1)[1]
    section = section.split("\n## ", 1)[0]

    assert site in section, site


def test_the_policy_pin_inventory_counts_five_and_not_four():
    """The count agrees with the inventory beside it."""
    flat = _flattened(SECURITY_POLICY)

    assert "load-bearing in **five** places" in flat
    assert "four places" not in flat
    assert CODE_LEVEL_PIN in flat


def test_the_code_level_pin_is_still_present_where_it_is_claimed():
    """The fifth site is asserted against the file, not just the prose."""
    module = REPO_ROOT / "backend" / "app" / "tasks" / "listing_updater.py"

    assert CODE_LEVEL_PIN in module.read_text(encoding="utf-8")


@pytest.mark.parametrize("site", PIN_SITES)
def test_every_document_that_lists_the_pin_sites_lists_the_same_ones(
    site,
):
    """The policy and the register do not disagree about the inventory."""
    for path in (SECURITY_POLICY, RESIDUAL_RISK_REGISTER):
        assert site in _text(path), str(path) + " omits " + site


def test_the_policy_defers_to_the_registers_single_inventory():
    """One inventory is maintained, and the other restates it."""
    flat = _flattened(SECURITY_POLICY)

    assert "docs/security/RESIDUAL_RISK.md" in flat
    assert "must not diverge from it" in flat


# --- Exposure and first-time provisioning are different things -----------


def test_the_runbook_scopes_its_compromise_claim_to_exposed_values():
    """The blanket claim is gone; the distinction is drawn instead.

    The opening said every credential was already compromised while the
    webhook identifier is explicitly new and was never committed.

    The count is four, not three: the listing-provider key was exposed
    through URL query strings and standard output rather than through the
    repository, so it is exposed without ever having been committed.
    Section 3 and ``SECURITY.md`` both name four, and this asserts the
    opening agrees with them.
    """
    text = _text(ROTATION_RUNBOOK)
    flat = _flattened(ROTATION_RUNBOOK)

    assert "### 1.2 Every previously exposed credential" in text
    assert "### 1.2 Every credential here is already compromised" not in text
    assert "**Four credentials were exposed**" in flat
    assert "For all four, do not reason about whether the value leaked" in flat
    assert "For the three previously exposed credentials" not in flat


def test_the_runbook_marks_the_webhook_identifier_as_provisioning():
    """Section 3.4 is labelled at its heading, not only in its body."""
    text = _text(ROTATION_RUNBOOK)
    flat = _flattened(ROTATION_RUNBOOK)

    # The section sits at 3.5 in the delivered runbook, because a
    # listing-provider key exposed through a log record was inserted at
    # 3.4. The label on the heading is what this asserts.
    assert (
        "### 3.5 PayPal webhook identifier "
        "(first-time provisioning, not rotation)"
    ) in text
    assert "Never exposed" in flat
    assert "First-time provisioning" in flat
    assert "not** incident response" in flat


def test_the_runbook_qualifies_the_four_step_sequence():
    """The four steps are claimed for the rotations, not for all four."""
    flat = _flattened(ROTATION_RUNBOOK)

    assert (
        "Every credential in [Section 3](#3-credentials-in-scope) is "
        "rotated by the same four steps"
    ) not in flat
    assert "Every **previously exposed** credential" in flat
    assert "steps 1 and 3 have nothing to act on" in flat


def test_the_runbook_verification_does_not_demand_an_order_that_cannot_exist():
    """First provisioning has no revocation to precede a rewrite.

    Four credentials were exposed, so the order is confirmed for four.
    Only three of them were committed, so the narrower claim that
    revocation preceded a history rewrite is scoped to those three, and
    the fourth is verified against the log purge instead.
    """
    flat = _flattened(ROTATION_RUNBOOK)

    assert "For each of the four **previously exposed** credentials" in flat
    assert "for the three that were committed" in flat
    assert "there is no order to confirm on first provisioning" in flat


# --- The environment-file contract states the delivered semantics ---------


def test_the_readme_describes_the_absolute_repository_root_default():
    """The default is anchored to the repository root, not the cwd."""
    flat = _flattened(README)

    assert "at the repository\nroot" in _text(README) or (
        "at the repository root" in flat
    )
    assert "by absolute path" in flat
    assert 'env_file = ".env"' not in flat


def test_the_readme_states_all_three_env_file_override_cases():
    """A path, a relative path and an empty value each behave stated."""
    flat = _flattened(README)

    assert "`ENV_FILE` in the process environment overrides that" in flat
    assert "resolved against the working" in flat
    assert "empty value to read no file at all" in flat
    assert "must not appear as a line inside the file" in flat


# --- The deployment section describes what actually ships ----------------


def test_the_readme_deployment_contract_matches_the_release_paths():
    """The documented contract is the delivered one, not an older one."""
    flat = _flattened(README)

    assert "-docker.pkg.dev" in flat
    assert "gcr.io`) is not used" in flat
    assert "infrastructure/docker/Dockerfile.backend" in flat
    assert "infrastructure/docker/Dockerfile.frontend" in flat
    assert "`backend` and `frontend`" in flat
    assert "immutable_tags = true" in flat
    assert "applied by digest" in flat
    assert "before** the rollout" in flat


def test_the_readme_records_the_retired_and_required_pipeline_inputs():
    """An operator learns which secret went away and what replaced it."""
    flat = _flattened(README)

    assert "`GKE_CLUSTER_ZONE` secret is retired" in flat
    for name in (
        "GKE_CLUSTER_REGION",
        "K8S_NAMESPACE",
        "ARTIFACT_REGISTRY_REPOSITORY",
        "GCP_WORKLOAD_IDENTITY_PROVIDER",
        "artifact_registry_writer_members",
        "cloud_function_invoker_member",
        "database_private_network",
    ):
        assert name in flat, name

    # The generic accessor input is gone, so the readme must not send an
    # operator looking for a variable this configuration no longer declares.
    assert "secret_accessor_members" not in flat


def test_the_readme_states_both_deliberate_release_blockers():
    """Neither blocker is left for an operator to discover at a keyboard.

    The second blocker read "No manifests are committed here" when this case
    was written, and that sentence would now be false: the workload inventory
    is committed under ``infrastructure/kubernetes/`` and rendered by
    ``scripts/render_kubernetes_manifests.sh``. What the blocker actually is
    survived the change -- nothing is created implicitly, so a release stops
    on a missing object rather than conjuring one -- and that is what this
    asserts.
    """
    flat = _flattened(README)

    assert "CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED" in flat
    assert "cloud_function_deployment_authorized" in flat
    assert "decommissioned" in flat
    assert "must not be advanced" in flat
    assert "declared here but applied by an operator" in flat
    assert "Nothing is created implicitly" in flat
    assert "A missing object stops the release" in flat


def test_the_readme_preserves_the_pinned_function_runtime():
    """Documenting the blocker does not document a bumped runtime."""
    flat = _flattened(README)

    assert "`python39`" in flat
    for forbidden in ("python310", "python311", "python312"):
        assert forbidden not in flat, forbidden


# --- Nothing above reintroduced a placeholder ----------------------------


@pytest.mark.parametrize(
    "path", [README, SECURITY_POLICY, ROTATION_RUNBOOK]
)
def test_no_operator_document_carries_an_unresolved_marker(path):
    """These documents are delivered, not drafted."""
    text = _text(path)

    for marker in (
        "HUMAN ASSISTANCE NEEDED",
        "TODO",
        "FIXME",
        "<INSTANCE_CONNECTION_NAME>",
    ):
        assert marker not in text, marker


# --- The Rule 1 artifacts describe the delivered change ------------------


def _status_path(line):
    """Returns the path one porcelain status line names.

    A rename is reported as ``old -> new``, and the path that has been
    delivered is the new one.
    """
    path = line[3:]
    _, arrow, renamed = path.partition(" -> ")
    return renamed if arrow else path


def _delivered_paths():
    """Returns every path this change delivers.

    A path is delivered when it is committed against the baseline -- the
    revision the matrix and the log both cite as the state before this
    remediation -- or when it is staged in the index, which is what a
    commit is assembled from.

    A path git does not track is not delivered. It is scratch until it is
    added, and adding it is what brings it into this set, so a validation
    byproduct sitting in a working tree neither has to be named in the
    matrix nor makes this case unrunnable locally. The byproduct filter
    below still applies, and covers a tracked path whose content is a
    validation artefact.
    """
    if not (REPO_ROOT / ".git").exists():
        pytest.skip("not a git checkout")

    def git(*args):
        result = subprocess.run(
            ["git"] + list(args),
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
        )
        if result.returncode != 0:
            pytest.skip("git is unavailable or the baseline is missing")
        return result.stdout

    paths = set()
    for line in git("diff", "--name-status", BASELINE_REVISION,
                    "HEAD").split("\n"):
        line = line.rstrip("\r")
        if line.strip():
            paths.add(line.split("\t")[-1])
    for line in git("status", "--porcelain").split("\n"):
        line = line.rstrip("\r")
        if not line.strip() or line[:2] == UNTRACKED_STATUS:
            continue
        paths.add(_status_path(line))

    return {
        path
        for path in paths
        if not path.startswith(BYPRODUCT_PREFIXES)
        and not path.endswith(BYPRODUCT_SUFFIXES)
        and ".terraform" not in path
    }


def _matrix_reverse_index():
    """Returns every target path the reverse index carries a row for."""
    text = _text(TRACEABILITY_MATRIX)
    section = text.split("## 4. Reverse index", 1)[1]
    #: The index ends where the next top-level section begins. Naming that
    #: section instead would silently widen the span the day it is renumbered,
    #: and a widened span swept in the schema and delivered-target tables,
    #: whose first column is a model attribute rather than a path.
    section = re.split(r"(?m)^## ", section, maxsplit=1)[0]
    return [
        m.group(1)
        for m in re.finditer(r"(?m)^\|\s*`([^`]+)`\s*\|", section)
    ]


def test_every_delivered_path_is_reachable_from_the_file_side():
    """The matrix indexes the whole change, not only the plan.

    It claimed bidirectional coverage with no gaps while omitting real
    delivered paths, so the claim could be disproved by listing the
    changed files. This case is that listing.
    """
    reverse = set(_matrix_reverse_index())
    missing = sorted(p for p in _delivered_paths() if p not in reverse)

    assert missing == [], (
        "these paths are committed or staged and the reverse index of "
        "%s carries no row for them: %s. Add a row for each path the "
        "change delivers; a path that is only a validation byproduct "
        "should be left untracked or removed instead."
        % (TRACEABILITY_MATRIX.name, ", ".join(missing))
    )


def test_the_reverse_index_carries_no_duplicate_row():
    """One row per path, so the count is a count of paths."""
    reverse = _matrix_reverse_index()

    assert len(reverse) == len(set(reverse))
    assert len(reverse) == MATRIX_REVERSE_ROWS


def test_the_matrix_publishes_a_reconcilable_delivered_total():
    """The totals add up, and say what they are counting."""
    flat = _flattened(TRACEABILITY_MATRIX)

    assert "### 2.9 Paths delivered beyond the plan" in _text(
        TRACEABILITY_MATRIX
    )
    assert "### 2.10 Delivered-path reconciliation" in _text(
        TRACEABILITY_MATRIX
    )
    #: The identity the document publishes for the index it delivers. Six
    #: earlier totals were published in succession -- 86, 91, 93, 141, 125
    #: and 129 -- each correct for the tree it measured and each left standing
    #: beside the next. Section 2.10 now carries one current measurement and
    #: lists those six as superseded snapshots, so both halves are asserted:
    #: the current identity has to be present and each snapshot has to be
    #: labelled.
    assert "`131 + 9 + 17 = 157`" in flat
    assert "`69 + 26 + 62 = 157`" in flat
    assert "`59 + 27 + 62 - 17 = 131`" in flat
    assert "Delivered paths absent from the reverse index | **0**" in flat
    for snapshot in (
        "**86**", "**91**", "**93**", "**141**", "**125**", "**129**"
    ):
        assert snapshot + " " in flat, snapshot
    assert flat.count("| **Superseded** |") >= 6

    # The plan's own figure is the one the frozen plan publishes: nine
    # reference entries and 68 in total. The plan additionally renders
    # backend/app/api/router.py as a reference row inside its application-core
    # group, which section 2.8 records as indexed and not counted.
    assert "`30 + 29 + 0 + 9 = 68`" in flat
    assert "`30 + 29 + 0 + 10 = 69`" not in flat

    # The boundary that used to disclaim a delivered total is withdrawn.
    assert (
        "**No delivered-path total, and no repository-wide file count.**"
        not in flat
    )


@pytest.mark.parametrize(
    "path",
    [
        "backend/.dockerignore",
        "setup.cfg",
        "backend/tests/security/test_payment_lifecycle.py",
        "backend/tests/security/test_rate_limit_store.py",
        "backend/tests/security/test_release_automation_contract.py",
        "backend/tests/security/test_operator_documentation.py",
    ],
)
def test_each_named_delivered_path_appears_in_both_directions(path):
    """The paths the review named, plus this round's own two modules."""
    text = _text(TRACEABILITY_MATRIX)
    forward = text.split("### 2.9 Paths delivered beyond the plan", 1)[1]
    forward = forward.split("### 2.10", 1)[0]

    assert path in forward, path
    assert path in _matrix_reverse_index(), path
    assert (REPO_ROOT / path).exists(), path


def test_the_decision_log_records_this_round_of_decisions():
    """Every grouping of this round's work has its own subsection."""
    text = _text(DECISION_LOG)

    #: This round arrived numbered 35 and is delivered as 84, because another
    #: round already held 35 by the time both were assembled. Section 87 of
    #: the log records the concordance, and the rule it states is the one
    #: applied here: the suffix is preserved and only the prefix changed, so
    #: every title below is asserted unaltered.
    for heading in (
        "## 84. Release automation, infrastructure and audit governance",
        "### 84.1 Audit governance",
        "### 84.2 Release automation",
        "### 84.3 Paths delivered beyond the plan, reconciled",
        "### 84.4 Infrastructure the release paths depend on",
        "### 84.5 The developer bootstrap contract",
        "### 84.6 Operator documentation",
        "### 84.7 Reconciliation of rows that no longer describe",
        "### 84.8 Traceability for this round",
        "### 84.9 Deliberate non-changes from this round",
        "### 84.10 The executive presentation",
    ):
        assert heading in text, heading


def test_the_decision_log_records_the_deck_truthfulness_decisions():
    """Rule 1 treats an unexplained deviation as a defect.

    Correcting the deck meant choosing between several defensible
    wordings, and one earlier draft of the placeholder sentence was
    wrong in the opposite direction. Both the choice and the rejected
    draft belong in the log rather than in a comment.
    """
    text = _text(DECISION_LOG)
    rows = [
        line
        for line in text.split("\n")
        if re.match(r"^\|\s*84\.10\.\d+\s*\|", line)
    ]

    assert len(rows) >= 7, len(rows)
    for row in rows:
        cells = [cell.strip() for cell in row.strip().strip("|").split("|")]
        assert len(cells) == 5, row
        assert all(cells), row

    flat = " ".join(text.split())
    assert "remediated in code" in flat
    assert "classed link" in flat
    assert "two refusal regimes" in flat
    assert "scratch repository" in flat


def test_the_matrix_names_the_automated_verifier_of_the_deck():
    """The deck's row no longer offers review as its only evidence.

    It was verified by reading until this round, which is why three
    untrue claims survived in it.
    """
    row = [
        line
        for line in _text(TRACEABILITY_MATRIX).split("\n")
        if line.startswith("| `blitzy-deck/executive-summary.html` |")
        and "test_operator_documentation.py" in line
    ]

    assert len(row) == 1, len(row)
    assert "F-25" in row[0]


def test_every_decision_row_in_this_round_carries_all_five_columns():
    """Rule 1 requires alternatives, rationale and risk, not just a claim."""
    text = _text(DECISION_LOG)
    section = text.split(
        "## 84. Release automation, infrastructure and audit governance", 1
    )[1]
    rows = [
        line
        for line in section.split("\n")
        if re.match(r"^\|\s*84\.\d+\.\d+\s*\|", line)
    ]

    assert len(rows) >= 30, len(rows)
    for row in rows:
        cells = [c.strip() for c in row.strip().strip("|").split("|")]
        assert len(cells) == 5, row[:80]
        for cell in cells:
            assert cell, row[:80]


def test_the_withdrawn_shellcheck_row_is_marked_rather_than_deleted():
    """Row 12.5's position changed, and the log says so.

    It recorded unquoted expansions in the release script as an accepted
    non-change. The script has since been rewritten and reports none.
    """
    text = _text(DECISION_LOG)
    row = [
        line for line in text.split("\n") if line.startswith("| 12.5 |")
    ]

    assert len(row) == 1
    assert "WITHDRAWN" in row[0]
    assert "84.7.1" in row[0]
    assert "| 84.7.1 |" in text


def test_this_round_traces_every_finding_it_answered():
    """Each finding identifier appears in the round's traceability table."""
    text = _text(DECISION_LOG)
    table = text.split("### 84.8 Traceability for this round", 1)[1]
    table = table.split("\n### ", 1)[0]

    for number in range(1, 31):
        identifier = "F-%02d" % number
        assert ("| " + identifier + " |") in table, identifier


def test_the_critical_decision_document_still_carries_exactly_five():
    """Rule 3's artifact carries the plan's five entries and no more.

    Only the five decisions are numbered sections, and the
    review-sequencing note that follows them is deliberately unnumbered
    so that it cannot be read as a sixth. An earlier revision numbered it
    six and additionally carried an appendix with its own Decision,
    Rationale and Reviewer sections, which was a sixth entry in
    everything but its heading.
    """
    text = CRITICAL_DECISIONS.read_text(encoding="utf-8")
    numbered = re.findall(r"(?m)^##\s+(\d+)\.", text)
    #: Only the summary table's rows, because an entry's own tables are
    #: numbered too -- the pin-site inventory among them -- and sweeping
    #: the whole document would count those as decisions.
    overview = text[text.index("## Summary"):text.index("## 1. ")]
    summary = [
        line
        for line in overview.split("\n")
        if re.match(r"^\|\s*[1-9]\s*\|", line)
    ]

    assert numbered == ["1", "2", "3", "4", "5"]
    assert "## Review sequencing and companion artefacts" in text
    assert "## 6." not in text
    assert "## Appendix" not in text
    assert len(summary) == 5, len(summary)

    #: The order and the risk framing are the Agent Action Plan's own, so
    #: they are asserted against it rather than against a ranking this
    #: document argued for itself: four authorization-and-irreversibility
    #: decisions at High, then the advisory acceptance at Medium.
    risks = [row.split("|")[3].strip() for row in summary]
    assert risks == ["**High**"] * 4 + ["**Medium**"], risks

    headings = re.findall(r"(?m)^##\s+\d+\.\s+(.*)$", text)
    assert headings[0].startswith("Rotate the exposed credentials")
    assert headings[1].startswith("Seed exactly one administrator")
    assert headings[2].startswith("Restrict `POST /listings/`")
    assert headings[3].startswith("Verify PayPal webhook signatures")
    assert headings[4].startswith(
        "Accept eight residual dependency advisories"
    )


def test_the_critical_decision_document_states_the_reconciled_total():
    """Its fifth entry sends a reviewer to check eight, not seven.

    The entry's own checks are executable instructions, so a stale count
    there would have a reviewer verify part of the accepted set. Two
    counts are wrong in opposite directions and both are refused: seven
    omits the development advisory, and fourteen is the figure from
    before the audit instrument moved to a manifest no audit reads, when
    six of the scanner's own dependencies were reported as this
    project's.
    """
    text = CRITICAL_DECISIONS.read_text(encoding="utf-8")
    flat = " ".join(text.split())

    assert "Accept eight residual dependency advisories" in flat
    assert "Accept seven residual dependency advisories" not in flat
    assert "Accept fourteen residual dependency advisories" not in flat
    assert "each of the eight has a compensating control" in flat
    assert "seven for `backend/requirements.txt`" in flat
    assert "one for `backend/requirements-dev.txt`" in flat


# ---------------------------------------------------------------------
# The executive deck.
#
# Rule 2's artifact is read by people who will read nothing else, so a
# claim it makes is the claim the organisation acts on. The defects
# found in it all overstated completion rather than getting a fact
# wrong: findings described as closed when they are remediated in code
# and not yet deployed; managed secret storage drawn as though it
# already fed the running workloads; and a configuration template
# described as carrying a safe default for every setting, when its
# signing-key placeholder is one startup deliberately refuses.
#
# The structural rules Rule 2 sets are asserted here as well. They held
# when the deck was reviewed, and the content corrections above added a
# slide and rewrote several others, so nothing but a check keeps them
# holding.
# ---------------------------------------------------------------------

#: Rule 2's deliverable.
EXECUTIVE_DECK = REPO_ROOT / "blitzy-deck" / "executive-summary.html"

#: Wording the deck carried while it overstated completion. Each entry
#: is the exact text that was removed, so a reappearance is a
#: regression rather than a paraphrase of one.
OVERSTATED_CLAIMS = (
    "Twenty security findings closed across",
    "findings closed, spanning four vulnerability clusters",
    "Every figure below is measured, not estimated.",
    "Managed secret storage now exists where there was none.",
    "class AUTHZ,HDR,VAULT hardened;",
    "every setting ships documented with a safe local default",
    "every setting has a safe local default",
    "Secured, verifiable, ready to review",
    "Rotating the exposed credentials is the required next step.",
)

#: Each gate standing between the delivered code and a first release,
#: with a phrase from the deck's own statement of it.
RELEASE_GATES = (
    ("private control plane", "Access is granted by permission"),
    ("image registry", "must be created and the release identity"),
    ("function runtime", "no longer accepts for new or updated"),
    #: The gate is real -- each path refuses to create the serving objects
    #: and stops if they are absent -- but the reason it used to give was
    #: not: the definitions are versioned here. The phrase pinned now is
    #: the corrected statement, so a reappearance of the old one is caught
    #: as the regression it would be. Row 92.13 of the decision log.
    ("external cluster objects", "cluster objects it will not create"),
)

#: Bounds Rule 2 places on the deck.
DECK_SECTION_BOUNDS = (12, 18)
DECK_MAX_BULLETS = 4
DECK_MAX_BULLET_WORDS = 40

#: Exact pin Rule 2 requires of every third-party asset.
DECK_PINNED_ASSETS = (
    "reveal.js@5.1.0/dist/reveal.css",
    "reveal.js@5.1.0/dist/reveal.js",
    "lucide@0.460.0/dist/umd/lucide.min.js",
    "mermaid@11.4.0/dist/mermaid.esm.min.mjs",
)

#: Component classes the inline theme has to define.
DECK_COMPONENT_CLASSES = (
    "kpi-card",
    "data-table",
    "callout",
    "icon-row",
    "slide-head",
    "eyebrow",
    "brand-lockup",
    "accent-bar",
    "mermaid",
    "lede",
)

#: Anything that makes a slide more than text.
DECK_VISUAL = re.compile(
    r'data-lucide=|class="mermaid"|<table|class="kpi-grid"'
    r'|class="icon-row"|class="accent-bar"'
)

#: One heading rendered inside a slide.
DECK_HEADING = re.compile(r"<h[1-4][^>]*>(.*?)</h[1-4]>", re.S)

#: The heading text that identifies each slide these cases address. A slide
#: is addressed by what it renders rather than by a marker comment, so a
#: case cannot pass against a label the slide itself does not carry.
DECK_SLIDE_HEADINGS = {
    "title": "apartment-finder-service",
    "headline metrics": "What the work delivered",
    "architecture overview": "Where the new controls sit",
    "secrets and platform": "Credentials are out of the code",
    "risk and mitigation": "Residual risk, and what holds it in check",
    "first release": "Four things an operator must settle first",
    "onboarding": "Everything needed to pick this up",
    "closing": "Ready for review",
}


def _deck():
    """Returns the deck as text with newlines normalised."""
    return _text(EXECUTIVE_DECK)


def _deck_sections():
    """Returns the body of every slide, in document order."""
    return re.findall(
        r"<section\b[^>]*>(.*?)</section>", _deck(), re.S
    )


def _deck_slide_headings():
    """Yields ``(section, headings)`` for every slide, in document order."""
    for section in re.findall(
        r"<section\b[^>]*>.*?</section>", _deck(), re.S
    ):
        yield section, [
            " ".join(re.sub(r"<[^>]+>", " ", heading).split())
            for heading in DECK_HEADING.findall(section)
        ]


def _deck_slide(marker):
    """Returns the one slide whose own heading identifies ``marker``."""
    heading = DECK_SLIDE_HEADINGS[marker]
    matched = [
        section
        for section, headings in _deck_slide_headings()
        if any(heading in rendered for rendered in headings)
    ]
    assert len(matched) == 1, marker + " matches " + str(len(matched))
    return matched[0]


def _deck_budget(body):
    """Returns one slide's bullet count and its body word count."""
    bullets = re.findall(r"<li>(.*?)</li>", body, re.S)
    words = sum(
        len(re.sub(r"<[^>]+>", " ", bullet).split()) for bullet in bullets
    )
    return len(bullets), words


@pytest.mark.parametrize("claim", OVERSTATED_CLAIMS)
def test_the_deck_carries_no_claim_it_overstated(claim):
    """None of the removed overstatements has returned.

    Each one read as a statement about a running system. Nothing has
    been deployed, so a reader acting on any of them would believe a
    release had happened.
    """
    assert claim not in _deck(), claim


def test_the_deck_title_hands_deployment_and_rotation_to_an_operator():
    """The opening scope line says what is done and what is not.

    It is the only line some readers will take away, so it carries the
    distinction rather than leaving it to a later slide. An earlier
    revision of this case required the line to say every finding was
    covered by an automated test, which the metric grid three lines later
    contradicted with fifteen and five.
    """
    slide = " ".join(_deck_slide("title").split())

    assert "remediated in code" in slide
    assert "fifteen proven by automated test" in slide
    assert "five carrying an operational step" in slide
    assert "each covered by an automated test" not in slide
    assert "Deployment and credential rotation remain for an operator" in (
        slide
    )


def test_the_deck_metrics_disclaim_a_deployed_environment():
    """The figures are attributed to code and tests, not to a service.

    Every number on that slide comes from a static scan, a manifest or
    a test run. Presented without that attribution they read as
    production telemetry.

    The disclaimer is bounded by what this repository can establish. It
    once read "nothing here has been released yet", which is a claim
    about a deployed environment rather than a disclaimer about one, and
    nothing here can verify it either way.
    """
    slide = " ".join(_deck_slide("headline metrics").split())

    assert "measured in code and tests" in slide
    assert "None of it is a statement about a deployed environment" in slide
    assert "which this repository cannot see" in slide
    assert "nothing here has been released yet" not in _deck()


def test_the_deck_counts_findings_as_remediated_and_tested():
    """The headline count states what was achieved, precisely.

    Twenty findings have a delivered fix. Calling them closed claims an
    operational outcome that rotation and deployment still gate, and
    claiming all twenty are covered by test contradicts the two cards
    beside the count, which report fifteen and five.
    """
    slide = " ".join(_deck_slide("headline metrics").split())

    assert "findings remediated in code" in slide
    assert "covered by tests" not in slide


#: The three places row 44.2.1 of the decision log requires the split to
#: appear, each with the deck marker of the slide that carries it. An
#: earlier revision reported twenty as covered by test on the title and
#: closing slides while the metric grid beside them reported fifteen and
#: five, so the artefact contradicted itself twice over.
ASSURANCE_SPLIT_SLIDES = ("title", "headline metrics", "closing")


@pytest.mark.parametrize("marker", ASSURANCE_SPLIT_SLIDES)
def test_the_assurance_split_is_reported_wherever_the_total_is(marker):
    """Fifteen proven by test and five needing an operator, everywhere."""
    slide = " ".join(_deck_slide(marker).split()).lower()

    assert "fifteen" in slide, marker
    assert "five" in slide, marker
    assert "proven by" in slide, marker


def test_the_deck_bounds_its_release_claim_to_what_it_can_show():
    """One unambiguous sentence, and one it is entitled to make.

    "No part of this has been deployed" reads as a verified fact about
    every environment this code could be running in, and this repository
    has no visibility into any of them. What it can state is that four
    gates stand before a first release and that none of them can be
    settled from inside a commit, which is checkable here.
    """
    deck = _deck()

    assert "Four gates stand before a first release" in deck
    assert "none can be settled from inside a commit" in deck
    assert "No part of this has been deployed" not in deck


def test_the_deck_closing_offers_review_rather_than_release():
    """The last slide is where a reader forms their conclusion.

    It previously read as a completion notice. It now states the two
    things still outstanding and what is being asked for.
    """
    slide = " ".join(_deck_slide("closing").split())

    assert (
        "Remediated and tested. Ready for your review, with four release"
        in slide
    )
    assert "settling the four release gates come next" in slide


def test_the_architecture_diagram_draws_secret_delivery_as_delivered():
    """The drawn secret path is the one the delivered definitions create.

    When this was first reviewed the containers were provisioned and
    nothing carried a value into a running workload, so the link was drawn
    broken. The delivered manifests changed that: the backend Deployment,
    the migration Job, the administrator-credential Job and the ingestion
    CronJob each mount a provider class through the secrets-store driver
    under the backend workload identity, so the chain exists in the
    definitions and is drawn as it is defined. That it has not been applied
    to a cluster is a separate claim, carried by the prose and by the
    open-items list rather than by a broken arrow, and asserted by
    ``test_the_deck_states_plainly_that_nothing_has_been_deployed`` and
    ``test_the_architecture_slide_states_what_delivery_still_needs``.
    """
    slide = _deck_slide("architecture overview")

    assert slide.count("VAULT[") == 1
    for node in ("VAULT[", "GRANT[", "IDENT[", "MIG["):
        assert node in slide, node
    for edge in (
        "] --&gt; GRANT",
        "GRANT --&gt; IDENT",
        "IDENT --&gt; API",
        "IDENT --&gt; INGEST",
        "IDENT --&gt; MIG",
    ):
        assert edge in slide, edge


def test_the_pending_style_is_visually_distinct_from_the_hardened_one():
    """The distinction survives for a reader who does not read labels.

    A viewer sees the diagram before any prose, so a component's state has
    to be carried by the drawing as well as by the words in the node. Two
    components are drawn in the pending style because nothing uses them:
    the browser client and the object storage. The secret-delivery chain is
    drawn hardened, which is what the definitions carry.
    """
    slide = _deck_slide("architecture overview")

    assert "classDef pending" in slide
    assert "stroke-dasharray:6 4" in slide
    assert "class CLIENT,PLATFORM pending;" in slide

    hardened = re.search(r"class ([A-Z,]+) hardened;", slide)
    assert hardened is not None
    marked = hardened.group(1).split(",")
    for node in ("VAULT", "GRANT", "IDENT", "AUTHZ", "HDR"):
        assert node in marked, (node, marked)


def test_the_architecture_slide_states_what_delivery_still_needs():
    """An unconnected node means nothing unless the slide says what it means.

    The chain is drawn as the definitions carry it, so the slide has to say
    that nothing has been applied and that two components are drawn
    unconnected on purpose rather than by mistake.
    """
    slide = " ".join(_deck_slide("architecture overview").split())

    assert "Secrets reach each workload through a per-secret read grant" in (
        slide
    )
    assert "Two components are drawn unconnected" in slide
    assert "not operational" in slide


def test_the_secrets_slide_agrees_with_the_diagram():
    """The cluster slide agrees with the diagram it sits beside.

    Both state the same two things: the delivery chain is declared, and it
    has not been applied to a cluster.
    """
    slide = " ".join(_deck_slide("secrets and platform").split())

    assert "read grants and workload identity are declared" in slide
    assert "delivery still pending" in slide


def test_the_deck_states_the_template_will_not_start_the_service():
    """The shipped template is not a working configuration.

    Its signing-key placeholder is on the denylist the settings
    validator refuses, so a reader told every setting has a safe local
    default would expect a start that cannot happen.
    """
    slide = " ".join(_deck_slide("risk and mitigation").split())

    assert "will not start it as delivered" in slide
    assert "the non-secret ones carry a working local default" in slide
    assert "signing key ships as a placeholder that startup refuses" in (
        slide
    )
    assert "refused anywhere but a local run" in slide


def test_the_deck_describes_the_refusal_the_validator_performs():
    """The two refusals are not the same, and the deck separates them.

    The signing-key placeholder is denied in every environment, so the
    shipped template cannot start the service anywhere. The remaining
    secret placeholders are tolerated on a local run and denied outside
    one. Collapsing the two would tell a reader a local start is
    impossible, which it is not once a key is generated.
    """
    slide = " ".join(_deck_slide("risk and mitigation").split())
    config = _text(REPO_ROOT / "backend" / "app" / "core" / "config.py")
    guarded = config.split("_PLACEHOLDER_GUARDED_FIELDS = (", 1)[1]
    guarded = guarded.split(")", 1)[0]

    assert "refuses outright" in slide
    assert "anywhere but a local run" in slide

    #: The signing key is refused by a field validator with no
    #: environment condition, so it is absent from the guarded set the
    #: local exemption applies to.
    assert '"SECRET_KEY"' not in guarded
    assert '"ZILLOW_API_KEY"' in guarded
    assert '"PAYPAL_CLIENT_SECRET"' in guarded
    assert '"SENDGRID_API_KEY"' in guarded
    assert 'values.get("ENVIRONMENT") == LOCAL_ENVIRONMENT' in config

    #: And the template really does ship the refused key.
    template = _text(ENVIRONMENT_TEMPLATE)
    shipped = [
        line
        for line in template.split("\n")
        if line.startswith("SECRET_KEY=")
    ]
    assert len(shipped) == 1, shipped
    value = shipped[0].split("=", 1)[1]
    assert "change_me" in value.lower() or len(value) < 32, value


def test_the_onboarding_slide_requires_the_placeholders_be_replaced():
    """Day-one guidance names the step that precedes a first start."""
    slide = " ".join(_deck_slide("onboarding").split())

    assert "placeholder secrets must be replaced before startup" in slide


@pytest.mark.parametrize("subject,phrase", RELEASE_GATES)
def test_the_deck_names_every_release_gate(subject, phrase):
    """All four gates are stated, each with its consequence.

    A risk slide that lists accepted advisories and a breaking change,
    while omitting the four things that stop a release outright, tells
    a reviewer the wrong thing to ask about.
    """
    slide = " ".join(_deck_slide("first release").split())

    assert phrase in slide, subject


def test_the_release_gate_slide_stands_on_its_own():
    """The gates are a slide of their own, not a risk-table footnote.

    They are the reason nothing has shipped, so they carry the same
    weight as the risk table rather than sitting inside it.
    """
    headings = [
        rendered
        for _, headings in _deck_slide_headings()
        for rendered in headings
    ]
    slide = " ".join(_deck_slide("first release").split())

    assert "Four things an operator must settle first" in headings
    assert "Residual risk, and what holds it in check" in headings
    assert "Four things an operator must settle first" in slide


def test_the_blocked_function_gate_agrees_with_the_delivered_pin():
    """The deck says the constraint was not raised, and it was not.

    Describing a blocked deployment while the tree had quietly moved
    the runtime forward would misreport the one decision an owner is
    being asked to make.
    """
    slide = " ".join(_deck_slide("first release").split())
    terraform = _text(
        REPO_ROOT / "infrastructure" / "terraform" / "main.tf"
    )
    script = _text(REPO_ROOT / "scripts" / "deploy.sh")

    assert "The version is a fixed constraint of this work" in slide
    assert "was not raised" in slide
    assert 'runtime     = "python39"' in terraform
    assert "python39" in script


def test_the_blocked_function_gate_agrees_with_the_release_paths():
    """A blocked step is what the delivered automation actually does.

    Both paths gate the function on an explicit owner authorisation and
    leave the rest of the release running, which is what the slide
    describes.
    """
    slide = " ".join(_deck_slide("first release").split())
    terraform = _text(
        REPO_ROOT / "infrastructure" / "terraform" / "main.tf"
    )
    script = _text(REPO_ROOT / "scripts" / "deploy.sh")

    assert "reports itself blocked rather than failing the release" in slide
    assert "quietly weakening the constraint" in slide
    assert "cloud_function_deployment_authorized" in terraform
    assert "CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED" in script


def test_the_deck_and_the_readme_name_the_same_release_blockers():
    """The two documents a reviewer reads together do not disagree."""
    slide = " ".join(_deck_slide("first release").split())
    readme = _flattened(README)

    assert "control plane is private" in slide
    assert "the private endpoint stays private" in readme
    assert "container.clusters.connect" in readme
    assert "python39" in readme


def test_the_deck_holds_the_section_count_rule_2_allows():
    """Twelve to eighteen slides, each identified by its own heading."""
    sections = _deck_sections()
    headings = [headings for _, headings in _deck_slide_headings()]
    low, high = DECK_SECTION_BOUNDS

    assert low <= len(sections) <= high, len(sections)
    assert len(headings) == len(sections)
    assert _deck().count("<section") == _deck().count("</section>")

    leading = [group[0] for group in headings if group]
    assert len(leading) == len(sections), leading
    assert len(set(leading)) == len(leading), leading


def test_every_deck_slide_carries_a_non_text_visual():
    """Rule 2 permits no text-only slide."""
    bare = [
        index
        for index, body in enumerate(_deck_sections(), 1)
        if not DECK_VISUAL.search(body)
    ]

    assert bare == [], bare


def test_no_deck_slide_exceeds_its_bullet_or_word_budget():
    """Four bullets and forty words of body text, per slide.

    The slide added for the release gates and the several rewritten for
    accuracy each grew, and a budget is only a budget if it is checked.
    """
    over = [
        (index, bullets, words)
        for index, body in enumerate(_deck_sections(), 1)
        for bullets, words in [_deck_budget(body)]
        if bullets > DECK_MAX_BULLETS or words > DECK_MAX_BULLET_WORDS
    ]

    assert over == [], over


def test_the_deck_carries_no_emoji_and_no_fenced_code():
    """Iconography is Lucide only, and no slide holds a code block."""
    text = _deck()

    assert [hex(ord(c)) for c in text if ord(c) > 0x2100] == []
    assert "```" not in text
    assert "<code" not in text
    assert "<svg" not in text
    assert len(re.findall(r'data-lucide="([^"]+)"', text)) >= 20


@pytest.mark.parametrize("asset", DECK_PINNED_ASSETS)
def test_the_deck_pins_every_third_party_asset(asset):
    """An unpinned asset changes the deck without the deck changing."""
    assert asset in _deck(), asset


def test_the_deck_references_no_unpinned_asset():
    """Every package reference carries an ``@version``."""
    assert not re.search(r"cdn\.jsdelivr\.net/npm/[a-z.\-]+/", _deck())


@pytest.mark.parametrize("component", DECK_COMPONENT_CLASSES)
def test_the_deck_theme_defines_every_component_class(component):
    """The theme is authored inline, so it has to be complete.

    Rule 2 cites a canonical theme stylesheet that this repository does
    not contain, and the deviation is recorded in the decision log; the
    consequence is that nothing external supplies a missing class.
    """
    assert component in _deck(), component


def test_the_deck_authors_its_theme_inline():
    """No external theme is fetched, and the custom properties are here."""
    text = _deck()

    assert "--blitzy-primary: #5B39F3;" in text
    assert "--gradient-hero:" in text
    assert "dist/theme/" not in text


def test_the_deck_carries_all_four_slide_types():
    """Title, divider, content and closing are all present."""
    text = _deck()

    assert 'class="slide-title"' in text
    assert 'class="slide-divider"' in text
    assert 'class="slide-closing"' in text
    assert text.count('class="slide-divider"') == 4


def test_the_deck_redraws_its_diagrams_on_every_slide_change():
    """A diagram on an unvisited slide has no layout box to measure.

    Deferred initialisation plus a redraw on each change is what makes
    the second diagram appear at all, so both hooks are required.
    """
    text = _deck()

    assert "startOnLoad: false" in text
    assert "Reveal.on('ready'" in text
    assert "Reveal.on('slidechanged'" in text
    assert text.count("mermaid.run(") >= 2
    for variable in (
        "primaryColor",
        "primaryTextColor",
        "primaryBorderColor",
        "lineColor",
        "secondaryColor",
    ):
        assert variable in text, variable


def test_the_deck_is_a_single_self_contained_file():
    """It opens from disk with no build step and no local asset."""
    text = _deck()
    local = [
        reference
        for reference in re.findall(r'(?:src|href)="([^"]+)"', text)
        if not reference.startswith(("http", "#", "data:"))
    ]

    assert "<html" in text and "</html>" in text
    assert local == [], local


def test_the_documented_start_command_leaves_the_client_address_alone():
    """The command an operator pastes carries the forwarded-header flag.

    Without it the ASGI server replaces the address the connection was
    made from with whatever an inbound ``X-Forwarded-For`` header claims,
    for any connection arriving from an address it trusts, so a caller
    varying that header is counted as a new client on every request and no
    per-caller rate limit engages. The container image and the deployment
    carry the same flag, which
    ``test_delivery_pipeline.py`` asserts.
    """
    block = _block_containing(README, ASGI_APP_MARKER)

    assert NO_PROXY_HEADERS_FLAG in block.split()


@pytest.mark.parametrize(
    "path", [README, ENVIRONMENT_TEMPLATE], ids=lambda path: path.name
)
def test_each_document_pairs_the_flag_with_the_hop_setting(path):
    """Both places the hop setting is read name what puts it in force.

    An operator setting a hop count on a server started without the flag
    is changing a value the server has already decided for them.
    """
    flat = _flattened(path)

    assert NO_PROXY_HEADERS_FLAG in flat, path.name
    assert HOP_SETTING in flat, path.name
    assert FORWARDED_ALLOW_FLAG in flat, path.name


def test_the_readme_row_for_the_hop_setting_names_the_flag():
    """The pairing is stated in the setting's own row, not elsewhere."""
    rows = [
        line
        for line in _text(README).split("\n")
        if line.startswith("|") and HOP_SETTING in line
    ]

    assert len(rows) == 1, len(rows)
    assert NO_PROXY_HEADERS_FLAG in rows[0]
    assert FORWARDED_ALLOW_FLAG in rows[0]


def test_the_template_block_for_the_hop_setting_names_the_flag():
    """The same holds where an operator writes the value."""
    lines = _text(ENVIRONMENT_TEMPLATE).split("\n")
    index = next(
        position
        for position, line in enumerate(lines)
        if line.startswith(HOP_SETTING + "=")
    )
    block = []
    while index > 0 and lines[index - 1].startswith("#"):
        index -= 1
        block.append(lines[index])
    commentary = " ".join(" ".join(reversed(block)).split())

    assert NO_PROXY_HEADERS_FLAG in commentary
    assert FORWARDED_ALLOW_FLAG in commentary


def test_this_module_reads_every_document_it_claims_to():
    """A guard against a path here drifting away from the tree."""
    for path in (
        README,
        SECURITY_POLICY,
        ROTATION_RUNBOOK,
        RESIDUAL_RISK_REGISTER,
        ENVIRONMENT_TEMPLATE,
        EXECUTIVE_DECK,
    ):
        assert path.is_file(), str(path)
        assert io.open(str(path), encoding="utf-8").read()
