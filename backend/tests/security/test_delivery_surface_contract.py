"""Checks over the workflows that verify and deploy the service.

Neither workflow can be executed from this test process -- doing so needs a
GitHub runner, a Google Cloud project and a cluster -- so every property
below is asserted against the declaration itself. What is asserted:

* both workflow files parse, and the continuous-integration workflow
  offers the ``workflow_call`` trigger the deployment workflow's gate
  needs in order to resolve
* deployment is gated on the whole continuous-integration workflow rather
  than on a subset of its checks, and the file it calls exists
* each workflow grants the narrowest token it can, and the federated
  exchange's ``id-token`` write sits on the deploying job alone
* every ``docker build`` names its Dockerfile with ``-f``, each named
  Dockerfile and context exists, and no context carries a default
  ``Dockerfile`` -- which is what makes the flag load-bearing rather than
  decorative
* every cluster address is regional, because the cluster Terraform
  declares is regional
* the post-deployment probe reads the readiness route, which answers only
  when the database is readable, rather than the liveness route, which
  answers throughout a database outage
* no image is built while a federated credential file is present in the
  workspace, and the name that file takes is ignored by version control
  and by every image build context
* the Python version pinned in both workflows is the pinned runtime

``backend.app.main`` is the authority for the route the probe reads,
``infrastructure/terraform/main.tf`` is the authority for whether the
cluster is regional or zonal, and the Dockerfiles on disk are the
authority for what a build may name. A change to any of them is compared
against this file rather than against a second copy of it.

The ordering case is the one whose reasoning is worth stating. The
authentication action writes a short-lived credential file into the
workspace and removes it when the job ends, so a ``docker build`` running
between those two moments can copy it into a layer. Building before
authenticating removes the opportunity, and the ignore rules remove it
again for anything that reaches a build context by another route.
"""

import json
import re
from pathlib import Path

import pytest
import yaml
from conftest import REPO_ROOT

from backend.app.core.config import Settings
from backend.app.main import READINESS_PATH

#: Workflow that verifies a change.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Workflow that deploys a verified change.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"

#: Terraform root module, the authority for the cluster's shape.
TERRAFORM_MAIN = REPO_ROOT / "infrastructure" / "terraform" / "main.tf"

#: Runtime pinned by the project. Held at this value deliberately.
PINNED_PYTHON = "3.9"

#: Name the authentication action gives the credential file it writes.
CREDENTIAL_ARTIFACT = "gha-creds-*.json"

#: Ignore rules required to cover that name at the root and below it.
CREDENTIAL_IGNORE_RULES = (
    CREDENTIAL_ARTIFACT,
    "**/" + CREDENTIAL_ARTIFACT,
)

#: Every ignore file that governs a path a build or a commit can reach.
IGNORE_FILES = (
    Path(".gitignore"),
    Path(".dockerignore"),
    Path("backend") / ".dockerignore",
    Path("frontend") / ".dockerignore",
)

#: Action that performs the federated credential exchange.
AUTHENTICATION_ACTION = "google-github-actions/auth"

#: npm major each Node major ships with, for the versions this project
#: could reasonably select. Only the majors are needed: the lockfile
#: format is the thing being read, and npm 7 is where it arrives.
BUNDLED_NPM = {"14": 6, "16": 8, "18": 9, "20": 10, "22": 10, "24": 11}

#: Action that selects the Python interpreter.
PYTHON_ACTION = "actions/setup-python"

#: Render invocation that emits the one-shot migration workload.
MIGRATION_RENDER = "render_kubernetes_manifests.sh migration"

#: Render invocation that emits the serving workloads.
WORKLOAD_RENDER = "render_kubernetes_manifests.sh workloads"

#: Manifest that declares the one-shot migration workload.
MIGRATION_MANIFEST = (
    REPO_ROOT / "infrastructure" / "kubernetes" / "60-migration-job.yaml"
)

#: Matches a ``docker build`` invocation and the rest of its command,
#: line continuations included, so its flags can be read as one string.
DOCKER_BUILD = re.compile(
    r"docker\s+build((?:[^\n]*\\\n)*[^\n]*)",
)

#: Matches the Dockerfile a build names.
DOCKERFILE_FLAG = re.compile(r"-f\s+\"?\$?\{?([A-Za-z0-9_./-]+)\}?\"?")

#: Matches the context a build ends with.
BUILD_CONTEXT = re.compile(r"(\./[A-Za-z0-9_./-]+)\s*$")

#: Matches the cluster resource's location in the Terraform root module.
CLUSTER_LOCATION = re.compile(
    r"resource\s+\"google_container_cluster\"[^{]*\{(.*?)\n\}",
    re.DOTALL,
)


def _text(path):
    """Returns one file's text."""
    return path.read_text(encoding="utf-8")


def _migration_step(workflow):
    """Returns the shell block of the step that migrates the schema."""
    blocks = [
        step["run"] for step in _steps(workflow, "deploy")
        if MIGRATION_RENDER in step.get("run", "")
    ]
    assert len(blocks) == 1, blocks
    return blocks[0]


def _repo_path(reference):
    """Resolves a workflow-relative reference against the repository.

    A leading ``./`` is removed as an exact prefix rather than as a set
    of characters, which would also strip the leading dot of a name such
    as ``.github``.
    """
    relative = reference[2:] if reference.startswith("./") else reference
    return REPO_ROOT / relative


def _workflow(path):
    """Returns a parsed workflow with its trigger key normalised.

    ``on`` is a YAML boolean keyword, so a workflow's trigger block
    arrives under ``True`` rather than under the string. Both spellings
    are checked so the helper does not depend on which the parser
    produced.
    """
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    triggers = document.get("on", document.get(True))
    assert triggers is not None, "%s declares no trigger" % path.name
    document["triggers"] = triggers
    return document


@pytest.fixture(scope="module")
def ci_workflow():
    """The parsed continuous-integration workflow."""
    return _workflow(CI_WORKFLOW)


@pytest.fixture(scope="module")
def cd_workflow():
    """The parsed continuous-deployment workflow."""
    return _workflow(CD_WORKFLOW)


def _steps(workflow, job):
    """Returns the steps of one job."""
    return workflow["jobs"][job].get("steps", [])


def _run_blocks(workflow, job):
    """Returns every shell block one job runs, in order."""
    return [step["run"] for step in _steps(workflow, job) if "run" in step]


def _shell(workflow, job):
    """Returns every shell block of one job joined into one string."""
    return "\n".join(_run_blocks(workflow, job))


def _uncommented(block):
    """Returns a shell block with its comment lines removed.

    Prose in a comment can carry any sequence of characters, so a claim
    about what a script *does* has to be made against its commands.
    """
    return "\n".join(
        line for line in block.splitlines()
        if not line.lstrip().startswith("#")
    )


def _step_index(workflow, job, predicate):
    """Returns the indices of the steps satisfying ``predicate``."""
    return [
        index for index, step in enumerate(_steps(workflow, job))
        if predicate(step)
    ]


def _uses(step, action):
    """Reports whether a step invokes the named action."""
    return str(step.get("uses", "")).startswith(action)


def _job_running(workflow, marker):
    """Returns the one job whose commands contain ``marker``.

    The delivery workflow publishes images from one job and reaches the
    cluster from another, so that the two run on different runners and
    only the second one holds cluster credentials. Which job holds a
    command is therefore found rather than named, and finding exactly one
    is itself the assertion: two jobs building the same image would mean
    two images could be published for one release.
    """
    holders = [
        name for name, job in workflow["jobs"].items()
        if "steps" in job and marker in _uncommented(_shell(workflow, name))
    ]
    assert len(holders) == 1, (marker, holders)
    return holders[0]


def _needs_chain(workflow, job):
    """Returns every job ``job`` waits for, directly or through others."""
    reached = set()
    pending = [job]
    while pending:
        current = workflow["jobs"].get(pending.pop(), {})
        declared = current.get("needs", [])
        if isinstance(declared, str):
            declared = [declared]
        for name in declared:
            if name not in reached:
                reached.add(name)
                pending.append(name)
    return reached


def _logical_lines(shell):
    """Returns the block's commands with continuations joined.

    A command written across continuations is one command, and a check
    that matched the source text literally would report it as absent the
    moment a flag was added on a line of its own.
    """
    joined = re.sub(r"\\\s*\n\s*", " ", _uncommented(shell))
    return [" ".join(line.split()) for line in joined.splitlines()]


class TestTheWorkflowsAreWellFormed:
    """Cases over the structure both workflow files must have."""

    def test_both_workflows_parse(self, ci_workflow, cd_workflow):
        """Asserts each workflow is a mapping of named jobs."""
        for workflow in (ci_workflow, cd_workflow):
            assert isinstance(workflow["jobs"], dict)
            assert workflow["jobs"], "a workflow declares no job"

    def test_the_verification_workflow_can_be_called(self, ci_workflow):
        """Asserts the trigger the deployment gate needs is offered.

        The deployment workflow reaches this workflow with ``uses``,
        which resolves only against a workflow that accepts
        ``workflow_call``.
        """
        assert "workflow_call" in ci_workflow["triggers"]

    def test_every_workflow_grants_read_only_by_default(
        self, ci_workflow, cd_workflow,
    ):
        """Asserts neither workflow inherits the broad default token."""
        for workflow in (ci_workflow, cd_workflow):
            assert workflow["permissions"] == {"contents": "read"}

    def test_only_the_deploying_job_may_mint_an_identity_token(
        self, cd_workflow,
    ):
        """Asserts the federated write sits only where it is used.

        Two jobs exchange a federated credential now -- one to publish
        the images and one to reach the cluster -- so naming a single job
        would either forbid a grant a step needs or permit one no step
        uses. The grant is compared against the jobs that actually invoke
        the exchange, which is the property either mistake breaks.
        """
        granted = {
            name for name, job in cd_workflow["jobs"].items()
            if job.get("permissions", {}).get("id-token") == "write"
        }
        exchanging = {
            name for name, job in cd_workflow["jobs"].items()
            if any(
                _uses(step, AUTHENTICATION_ACTION)
                for step in job.get("steps", [])
            )
        }
        assert granted == exchanging, (granted, exchanging)
        assert granted, "no job exchanges a federated credential"


class TestDeploymentIsGatedOnFullVerification:
    """Cases over what must pass before a deployment starts."""

    def test_the_deploying_job_waits_for_the_verification_job(
        self, cd_workflow,
    ):
        """Asserts the deploying job cannot start before the gate.

        The image build was separated onto its own job between the two,
        so the dependency is now reached through that job rather than
        declared directly. Following the chain is what keeps the property
        -- nothing deploys until the whole gate passed -- asserted
        whatever sits in between.
        """
        chain = _needs_chain(cd_workflow, "deploy")
        assert "verify" in chain, chain

    def test_the_gate_calls_the_whole_verification_workflow(
        self, cd_workflow,
    ):
        """Asserts the gate is the CI workflow, not a subset of it.

        Calling the workflow rather than restating some of its steps is
        what keeps the gate and the checks from drifting apart: a check
        added to continuous integration gates deployment with no change
        here.
        """
        called = cd_workflow["jobs"]["verify"]["uses"]
        assert called == "./.github/workflows/ci.yml", called
        assert _repo_path(called).is_file(), called

    def test_the_gate_runs_no_steps_of_its_own(self, cd_workflow):
        """Asserts the gate job adds nothing beside the called workflow."""
        assert "steps" not in cd_workflow["jobs"]["verify"]


class TestEveryImageBuildNamesItsDockerfile:
    """Cases over how the deployment workflow builds its images."""

    def test_the_workflow_builds_both_images(self, cd_workflow):
        """Asserts a build exists for the backend and the frontend."""
        job = _job_running(cd_workflow, "docker build")
        shell = _uncommented(_shell(cd_workflow, job))
        assert len(DOCKER_BUILD.findall(shell)) == 2

    def test_every_build_names_a_dockerfile_that_exists(self, cd_workflow):
        """Asserts each build passes ``-f`` and the target is present.

        The declared value may be an environment reference, so the name
        is resolved through the workflow's ``env`` block before the path
        is checked.
        """
        environment = cd_workflow["env"]
        job = _job_running(cd_workflow, "docker build")
        shell = _uncommented(_shell(cd_workflow, job))
        named = []
        for command in DOCKER_BUILD.findall(shell):
            flag = DOCKERFILE_FLAG.search(command)
            assert flag is not None, command
            reference = flag.group(1)
            path = environment.get(reference, reference)
            assert (REPO_ROOT / path).is_file(), path
            named.append(path)
        assert len(set(named)) == 2, named

    def test_every_build_context_exists(self, cd_workflow):
        """Asserts each build ends with a directory that is present."""
        job = _job_running(cd_workflow, "docker build")
        shell = _uncommented(_shell(cd_workflow, job))
        assert DOCKER_BUILD.findall(shell), "no build found"
        for command in DOCKER_BUILD.findall(shell):
            context = BUILD_CONTEXT.search(command.replace("\\", ""))
            assert context is not None, command
            resolved = _repo_path(context.group(1))
            assert resolved.is_dir(), context.group(1)

    def test_no_build_context_carries_a_default_dockerfile(
        self, cd_workflow,
    ):
        """Asserts the ``-f`` flag is load-bearing for every build.

        A build with no ``-f`` reads ``Dockerfile`` from the root of its
        context. No context here holds one, so omitting the flag fails
        the build rather than building something unintended -- and this
        case is what keeps that true.
        """
        job = _job_running(cd_workflow, "docker build")
        shell = _uncommented(_shell(cd_workflow, job))
        assert DOCKER_BUILD.findall(shell), "no build found"
        for command in DOCKER_BUILD.findall(shell):
            context = BUILD_CONTEXT.search(command.replace("\\", ""))
            resolved = _repo_path(context.group(1))
            assert not (resolved / "Dockerfile").exists(), resolved.name


class TestEveryClusterAddressIsRegional:
    """Cases over how the workflow addresses the cluster."""

    def test_terraform_declares_a_regional_cluster(self):
        """Asserts the authority for the address form says regional.

        A cluster whose ``location`` is a region is regional and is
        addressed with ``--region``; one whose location is a zone is
        zonal and is addressed with ``--zone``. This reads the
        declaration so the cases below rest on it rather than on a
        restatement of it.
        """
        body = CLUSTER_LOCATION.search(
            TERRAFORM_MAIN.read_text(encoding="utf-8"),
        )
        assert body is not None, "no cluster resource found"
        assert re.search(r"location\s*=\s*var\.region", body.group(1))

    def test_the_workflow_addresses_the_cluster_regionally(
        self, cd_workflow,
    ):
        """Asserts the credential fetch passes a region."""
        shell = _uncommented(_shell(cd_workflow, "deploy"))
        assert "get-credentials" in shell
        assert "--region" in shell

    def test_no_zonal_address_survives(self, cd_workflow):
        """Asserts nothing addresses the cluster by zone."""
        shell = _uncommented(_shell(cd_workflow, "deploy"))
        assert "--zone" not in shell
        assert "GKE_ZONE" not in cd_workflow["env"]


class TestThePostDeploymentProbeReadsReadiness:
    """Cases over what the workflow checks after a rollout."""

    def test_the_probe_reads_the_readiness_route(self, cd_workflow):
        """Asserts the gate is the route that reads the database.

        The liveness route answers 200 whatever state the database is
        in, so it cannot distinguish a healthy release from one whose
        database is unreachable. The readiness route can.
        """
        shell = _uncommented(_shell(cd_workflow, "deploy"))
        assert READINESS_PATH in shell

    def test_the_probe_fails_the_job_when_readiness_never_answers(
        self, cd_workflow,
    ):
        """Asserts an unready release ends the job non-zero."""
        probe = [
            block for block in _run_blocks(cd_workflow, "deploy")
            if READINESS_PATH in block
        ]
        assert len(probe) == 1, len(probe)
        body = _uncommented(probe[0])
        assert "--fail" in body
        assert "exit 1" in body

    def test_the_probe_waits_for_both_rollouts_first(self, cd_workflow):
        """Asserts the probe runs against a completed rollout."""
        probe = [
            block for block in _run_blocks(cd_workflow, "deploy")
            if READINESS_PATH in block
        ][0]
        assert probe.index("rollout status") < probe.index(READINESS_PATH)


class TestTheSchemaIsMigratedBeforeTheRollout:
    """Cases over when the workflow applies migrations.

    A migration that runs after the rollout runs inside a pod already
    serving traffic against a schema the new code expects and the
    database does not yet have. Running it first, from the image about to
    be rolled out, and refusing to continue unless it succeeded, is what
    keeps the schema from trailing the code that reads it.
    """

    def test_the_migration_runs_before_any_image_is_rolled_out(
        self, cd_workflow,
    ):
        """Asserts the migration step precedes the rollout step.

        The rollout is an apply of the rendered workload manifests, which
        already carry this release's image, rather than an in-place image
        mutation on a live Deployment. The ordering property is unchanged;
        what changed is which command performs the rollout, so the absence
        of the mutating form is asserted as well.
        """
        migrations = _step_index(
            cd_workflow, "deploy",
            lambda step: MIGRATION_RENDER in step.get("run", ""),
        )
        rollouts = _step_index(
            cd_workflow, "deploy",
            lambda step: WORKLOAD_RENDER in step.get("run", ""),
        )
        assert migrations and rollouts, (migrations, rollouts)
        assert max(migrations) < min(rollouts), (migrations, rollouts)
        assert "kubectl set image" not in _shell(cd_workflow, "deploy")

    def test_the_migration_runs_the_image_being_deployed(self, cd_workflow):
        """Asserts the migration uses the image built in this run.

        Migrating with the image about to serve traffic is what makes the
        schema and the code that reads it the same revision.
        """
        body = _uncommented(_migration_step(cd_workflow))
        # The job is named for the tag the resolve step recorded, and the
        # manifests are rendered with that same tag, so the migration and
        # the rollout carry one image reference between them. The tag is
        # the verified commit rather than ``github.sha``: this workflow is
        # triggered by a completed run of another, and in that trigger
        # ``github.sha`` is the default branch's tip rather than the commit
        # that passed the gate.
        assert "MIGRATION_JOB_NAME" in body
        assert MIGRATION_RENDER in body
        assert cd_workflow["env"]["IMAGE_TAG"] == (
            "${{ github.event.workflow_run.head_sha }}"
        )
        assert "upgrade" in _text(MIGRATION_MANIFEST)
        assert "head" in _text(MIGRATION_MANIFEST)

    def test_a_failed_migration_ends_the_job(self, cd_workflow):
        """Asserts the job stops unless the migration reports success.

        The pod is polled rather than waited on, so the terminal phase
        has to be compared against success explicitly; anything else,
        including a poll that never saw a phase at all, has to be
        treated as a failure.
        """
        body = _uncommented(_migration_step(cd_workflow))
        # Completion is waited for rather than polled, so the terminal
        # state is the wait's own exit status; a wait that times out is a
        # failure without a phase ever having to be compared.
        assert "--for=condition=complete" in body
        guard = body.index("--for=condition=complete")
        assert "exit 1" in body[guard:], "no non-zero exit after the wait"

    def test_the_migration_pod_is_removed_whatever_happens(
        self, cd_workflow,
    ):
        """Asserts the one-shot workload does not outlive its release.

        A shell trap removed it while the step was a pod created by the
        runner. The workload is a Job declared in the manifests now, so
        the cluster removes it on its own timer -- which also holds when
        the runner is cancelled or lost part-way through, where a trap
        would not have run at all.
        """
        manifest = _text(MIGRATION_MANIFEST)
        assert "ttlSecondsAfterFinished:" in manifest
        assert "activeDeadlineSeconds:" in manifest
        assert "restartPolicy: Never" in manifest
        assert "kubectl run" not in _shell(cd_workflow, "deploy")


class TestNoCredentialIsPresentWhileAnImageIsBuilt:
    """Cases over the federated credential file's exposure window."""

    def test_every_build_precedes_the_credential_exchange(
        self, cd_workflow,
    ):
        """Asserts no build runs while the credential file exists."""
        job = _job_running(cd_workflow, "docker build")
        steps = _steps(cd_workflow, job)
        builds = _step_index(
            cd_workflow, job,
            lambda step: "docker build" in _uncommented(step.get("run", "")),
        )
        exchanges = _step_index(
            cd_workflow, job,
            lambda step: _uses(step, AUTHENTICATION_ACTION),
        )
        assert builds and exchanges, (builds, exchanges)
        assert max(builds) < min(exchanges), (builds, exchanges)
        assert len(steps) > max(exchanges)

    def test_every_push_follows_the_credential_exchange(self, cd_workflow):
        """Asserts the registry push still has a credential to use."""
        job = _job_running(cd_workflow, "docker push")
        pushes = _step_index(
            cd_workflow, job,
            lambda step: "docker push" in _uncommented(step.get("run", "")),
        )
        exchanges = _step_index(
            cd_workflow, job,
            lambda step: _uses(step, AUTHENTICATION_ACTION),
        )
        assert pushes, pushes
        assert min(pushes) > max(exchanges), (pushes, exchanges)

    def test_the_credential_file_is_removed_when_the_job_ends(
        self, cd_workflow,
    ):
        """Asserts the exchange is asked to clean up after itself."""
        exchanges = [
            step
            for job in cd_workflow["jobs"].values()
            for step in job.get("steps", [])
            if _uses(step, AUTHENTICATION_ACTION)
        ]
        assert exchanges, "no credential exchange found"
        for step in exchanges:
            assert step["with"]["cleanup_credentials"] is True

    @pytest.mark.parametrize(
        "ignore_file", IGNORE_FILES, ids=lambda path: str(path),
    )
    def test_the_credential_name_is_ignored_everywhere(self, ignore_file):
        """Asserts each ignore file covers the name at every depth.

        The exact rule covers the workspace root, where the action
        writes the file. The recursive rule covers a build context
        nested below it, which the exact rule alone does not reach in
        every one of these formats.
        """
        path = REPO_ROOT / ignore_file
        assert path.is_file(), str(ignore_file)
        rules = [
            line.strip() for line in path.read_text(encoding="utf-8")
            .splitlines() if line.strip()
        ]
        for required in CREDENTIAL_IGNORE_RULES:
            assert required in rules, (str(ignore_file), required)
        for rule in rules:
            assert rule != "!" + CREDENTIAL_ARTIFACT, str(ignore_file)


class TestNoCheckCanSuppressAnother:
    """Cases over the verification workflow's job topology.

    Every step of the verification workflow ran in one job before, and a
    runner ends a job at its first failing step. A frontend step that
    could not succeed therefore stopped the dependency audit, the static
    analysis, the compensating-control guards and the security suite from
    running at all. Splitting the checks across jobs that declare no
    dependency on each other is what makes each of them report on its
    own.
    """

    def test_the_checks_are_spread_across_several_jobs(self, ci_workflow):
        """Asserts the workflow is not one job doing everything."""
        assert len(ci_workflow["jobs"]) >= 2, list(ci_workflow["jobs"])

    def test_no_job_waits_for_another(self, ci_workflow):
        """Asserts no job can be skipped by another job's failure."""
        waiting = {
            name: job["needs"]
            for name, job in ci_workflow["jobs"].items() if "needs" in job
        }
        assert waiting == {}, waiting

    def test_the_backend_and_frontend_checks_are_separate_jobs(
        self, ci_workflow,
    ):
        """Asserts a frontend failure cannot hide a backend result."""
        holders = {}
        for marker in ("bandit", "npx --no-install eslint"):
            holders[marker] = {
                name for name in ci_workflow["jobs"]
                if marker in _uncommented(_shell(ci_workflow, name))
            }
        assert all(holders.values()), holders
        assert not holders["bandit"] & holders["npx --no-install eslint"], (
            holders
        )

    @pytest.mark.parametrize(
        "gate",
        (
            "pip-audit --strict -r backend/requirements.txt",
            "pip-audit --strict -r backend/requirements-dev.txt",
            "bandit -r backend/app -ll",
            "! pip show python-multipart",
            "--include=*.py backend/",
            "python -m pytest backend/tests --cov=backend/app",
            "python -m pytest backend/tests/security",
        ),
    )
    def test_every_backend_gate_is_still_invoked(self, ci_workflow, gate):
        """Asserts no backend gate was lost in the split.

        A gate is matched as a command rather than as a run of source
        characters: every token it names has to appear on one logical
        line, continuations joined. A gate written across continuations,
        or carrying a flag between two of these tokens, is the same gate
        -- and a literal match would have called it missing.
        """
        lines = [
            line
            for name in ci_workflow["jobs"]
            for line in _logical_lines(_shell(ci_workflow, name))
        ]
        tokens = gate.split()
        assert any(
            all(token in line for token in tokens) for line in lines
        ), gate

    def test_every_suppressed_advisory_is_registered_somewhere(
        self, ci_workflow,
    ):
        """Asserts no advisory is silenced without a written record.

        The runtime register covers the runtime manifest alone and says
        so, and the development manifest carries its own accepted list,
        so an identifier is looked for in both.
        """
        shell = "\n".join(
            _shell(ci_workflow, name) for name in ci_workflow["jobs"]
        )
        identifiers = re.findall(r"--ignore-vuln\s+(\S+)", shell)
        assert len(identifiers) >= 7, identifiers
        registries = "".join(
            (REPO_ROOT / name).read_text(encoding="utf-8") for name in (
                "docs/security/RESIDUAL_RISK.md",
                "backend/requirements-dev.txt",
            )
        )
        missing = [
            identifier for identifier in identifiers
            if identifier not in registries
        ]
        assert missing == [], missing


class TestEveryInvokedCommandExists:
    """Cases over whether the workflows call things that are there."""

    def test_every_npm_script_invoked_is_declared(
        self, ci_workflow, cd_workflow,
    ):
        """Asserts no step runs an npm script the package lacks.

        A missing script makes npm exit non-zero, which failed the job
        before anything after it ran. The package manifest is the
        authority for which names exist.
        """
        manifest = json.loads(
            (REPO_ROOT / "frontend" / "package.json")
            .read_text(encoding="utf-8"),
        )
        declared = set(manifest.get("scripts", {}))
        for workflow in (ci_workflow, cd_workflow):
            shell = "\n".join(
                _uncommented(_shell(workflow, name))
                for name, job in workflow["jobs"].items() if "steps" in job
            )
            for invoked in re.findall(r"npm run ([A-Za-z0-9:_-]+)", shell):
                assert invoked in declared, (invoked, sorted(declared))

    def test_the_frontend_lint_runs_a_command_that_is_installed(
        self, ci_workflow,
    ):
        """Asserts linting is invoked directly rather than by script.

        The package manifest is read-only reference material here and
        declares no lint script, so the check is invoked through the
        installed binary instead.
        """
        shell = "\n".join(
            _uncommented(_shell(ci_workflow, name))
            for name in ci_workflow["jobs"]
        )
        assert "npx --no-install eslint" in shell
        manifest = json.loads(
            (REPO_ROOT / "frontend" / "package.json")
            .read_text(encoding="utf-8"),
        )
        assert "eslint" not in manifest.get("scripts", {})

    def test_the_lockfile_is_readable_by_the_selected_package_manager(
        self, ci_workflow,
    ):
        """Asserts the npm that installs can read the lockfile.

        The lockfile is a format npm 7 introduced. When this case was
        written the workflow pinned a Node major whose bundled npm predates
        that format, so a newer npm had to be installed first; the pin has
        since moved to a major that bundles one new enough, which is the
        same property reached without an extra step. Either satisfies it,
        and a pin moving back to a Node whose npm cannot read the file
        fails here rather than at the install.
        """
        lockfile = json.loads(
            (REPO_ROOT / "frontend" / "package-lock.json")
            .read_text(encoding="utf-8"),
        )
        if lockfile.get("lockfileVersion", 1) < 2:
            pytest.skip("the lockfile predates the format npm 7 introduced")
        installing = 0
        for name, job in ci_workflow["jobs"].items():
            shell = _uncommented(_shell(ci_workflow, name))
            if "npm ci" not in shell:
                continue
            installing += 1
            selected = re.search(r"npm install -g npm@(\d+)", shell)
            if selected is not None:
                assert int(selected.group(1)) >= 7, selected.group(1)
                assert (
                    shell.index("npm install -g npm@") < shell.index("npm ci")
                )
                continue
            pinned = [
                str(step["with"]["node-version"])
                for step in job.get("steps", [])
                if _uses(step, "actions/setup-node")
                and "node-version" in step.get("with", {})
            ]
            assert len(pinned) == 1, (name, pinned)
            major = pinned[0].split(".")[0]
            assert major in BUNDLED_NPM, (name, pinned[0])
            assert BUNDLED_NPM[major] >= 7, (name, pinned[0])
        assert installing, "no job installs the frontend dependencies"


class TestNoGateIsAPlaceholder:
    """Cases over steps that would pass without checking anything."""

    @pytest.mark.parametrize("workflow_path", (CI_WORKFLOW, CD_WORKFLOW))
    def test_no_workflow_carries_a_manual_assistance_marker(
        self, workflow_path,
    ):
        """Asserts no step defers its work to a reader."""
        body = workflow_path.read_text(encoding="utf-8")
        assert "HUMAN ASSISTANCE" not in body, workflow_path.name

    @pytest.mark.parametrize("which", ("ci", "cd"))
    def test_no_step_runs_only_comments(self, which, ci_workflow, cd_workflow):
        """Asserts every shell step actually executes something.

        A block holding only comments is a step that always succeeds
        while checking nothing, which reads from the outside exactly
        like a passing gate.
        """
        workflow = ci_workflow if which == "ci" else cd_workflow
        empty = []
        for name, job in workflow["jobs"].items():
            if "steps" not in job:
                continue
            for step in job["steps"]:
                if "run" not in step:
                    continue
                if not _uncommented(step["run"]).strip():
                    empty.append((name, step.get("name", "?")))
        assert empty == [], empty

    def test_the_integration_gate_exercises_the_running_service(
        self, ci_workflow,
    ):
        """Asserts the integration job does real work against real parts.

        Each marker below is a thing the gate could not assert without a
        database and a served application: applying the revision chain,
        stepping it back, importing the entrypoint, and reading the
        routes over HTTP.
        """
        integration = [
            name for name, job in ci_workflow["jobs"].items()
            if "services" in job
        ]
        # Several jobs attach a database now rather than one, because the
        # checks that need a real dialect were split so that no one of them
        # can be skipped by another's failure. Each marker is therefore
        # required of the set rather than of a single job, and every job in
        # the set has to attach the real service rather than a stub.
        assert integration, integration
        shell = "\n".join(
            _uncommented(_shell(ci_workflow, name)) for name in integration
        )
        for marker in (
            "alembic -c backend/alembic.ini upgrade head",
            "alembic -c backend/alembic.ini downgrade -1",
            "import backend.app.main",
            "uvicorn backend.app.main:app",
            READINESS_PATH,
            "/auth/login",
            "access_token",
        ):
            assert marker in shell, marker
        for name in integration:
            declared = json.dumps(ci_workflow["jobs"][name]["services"])
            assert "postgres" in declared, name

    def test_the_integration_gate_supplies_every_required_setting(
        self, ci_workflow,
    ):
        """Asserts the job declares each setting that has no default.

        A missing one stops the application importing, so the gate would
        fail for a reason unrelated to what it is testing.
        """
        integration = [
            name for name, job in ci_workflow["jobs"].items()
            if "services" in job
        ][0]
        job = ci_workflow["jobs"][integration]
        supplied = set(job.get("env", {}))
        generated = re.findall(
            r'echo "([A-Z_]+)=', _shell(ci_workflow, integration),
        )
        supplied.update(generated)
        required = {
            name for name, field in Settings.__fields__.items()
            if field.required
        }
        assert required, "no required setting found"
        assert required <= supplied, sorted(required - supplied)


class TestThePinnedRuntimeIsUnchanged:
    """Cases over the runtime pin both workflows carry."""

    def test_every_interpreter_selection_pins_the_runtime(
        self, ci_workflow, cd_workflow,
    ):
        """Asserts no workflow step selects another interpreter.

        The pin is load-bearing: the ingestion task uses a decorator
        removed in a later interpreter, so advancing it here would
        break code this project does not change.
        """
        selections = []
        for workflow in (ci_workflow, cd_workflow):
            for job in workflow["jobs"]:
                for step in _steps(workflow, job):
                    if _uses(step, PYTHON_ACTION):
                        selections.append(step["with"]["python-version"])
        assert selections, "no interpreter selection found"
        assert set(selections) == {PINNED_PYTHON}, selections
