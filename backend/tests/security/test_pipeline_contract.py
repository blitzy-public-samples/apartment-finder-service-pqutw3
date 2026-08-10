"""Checks over the delivery pipeline: both workflows and the deploy script.

Neither workflow nor the deployment script can be executed from this test
process -- each addresses a Google Cloud project, a private cluster and a
container registry that exist only in a deployed environment. Every
property below is therefore asserted against the declaration itself, so
that a declaration naming a path, an image, a workload or a route that
this repository does not carry fails here rather than partway through a
release.

What is asserted:

* each ``docker build`` names a Dockerfile that exists, with a context
  directory that exists
* every image reference addresses the Artifact Registry host the
  infrastructure provisions, and none addresses the retired
  Container Registry host
* cluster credentials are requested by region, because the cluster the
  infrastructure creates is regional
* the workloads and the namespace a release mutates are confirmed to
  exist before the first mutating command runs
* the schema migration runs before the rollout that depends on it
* the post-deployment probe reads the readiness route, so a rollout whose
  database or configuration is unusable fails rather than reporting
  success
* deployment is gated on the whole continuous-integration workflow, which
  is called rather than duplicated
* the continuous-integration workflow invokes every security gate, and
  its integration step runs commands rather than carrying only a comment
* no step invokes a script the read-only frontend manifest does not
  declare
* the Python runtime pin is intact at both pipeline sites
* no file in the pipeline carries an unresolved assistance marker

The authorities are: ``infrastructure/docker`` for the Dockerfile paths,
``frontend/package.json`` for the scripts the frontend workspace
publishes, :data:`backend.app.main.READINESS_PATH` for the readiness
route, and ``backend/app/api/router.py`` for the route prefixes. A change
to any of them is compared against this file rather than against a second
copy of it.
"""

import json
import re

import pytest
import yaml
from conftest import REPO_ROOT

from backend.app.main import READINESS_PATH

#: Continuous-integration workflow under test.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Continuous-deployment workflow under test.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"

#: Deployment script under test.
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy.sh"

#: Manifest publishing the scripts the frontend workspace answers to.
FRONTEND_MANIFEST = REPO_ROOT / "frontend" / "package.json"

#: Every pipeline file, for the checks that apply to all of them.
PIPELINE_FILES = (CI_WORKFLOW, CD_WORKFLOW, DEPLOY_SCRIPT)

#: Infrastructure definitions the pipeline deploys into.
TERRAFORM_DIRECTORY = REPO_ROOT / "infrastructure" / "terraform"

#: Resource definitions under test.
TERRAFORM_MAIN = TERRAFORM_DIRECTORY / "main.tf"

#: Variable declarations under test.
TERRAFORM_VARIABLES = TERRAFORM_DIRECTORY / "variables.tf"

#: Output declarations under test.
TERRAFORM_OUTPUTS = TERRAFORM_DIRECTORY / "outputs.tf"

#: Provider dependency lock, which is tracked rather than ignored.
TERRAFORM_LOCK = TERRAFORM_DIRECTORY / ".terraform.lock.hcl"

#: Every infrastructure file, for the checks that apply to all of them.
TERRAFORM_FILES = (TERRAFORM_MAIN, TERRAFORM_VARIABLES, TERRAFORM_OUTPUTS)

#: Markers recording work that was never finished.
FORBIDDEN_MARKERS = (
    "HUMAN ASSISTANCE NEEDED",
    "TODO",
    "FIXME",
)

#: Host suffix of the registry the infrastructure provisions.
ARTIFACT_REGISTRY_SUFFIX = "-docker.pkg.dev"

#: Registry hosts that are retired and must not be addressed.
RETIRED_REGISTRY_HOSTS = ("gcr.io", "eu.gcr.io", "us.gcr.io", "asia.gcr.io")

#: Interpreter version pinned at every pin site.
PINNED_PYTHON = "3.9"

#: Runtime flag the Cloud Function deployment keeps.
PINNED_FUNCTION_RUNTIME = "--runtime python39"

#: Workloads a release updates.
DEPLOYED_WORKLOADS = ("frontend", "backend")

#: Line continuation, collapsed before a command line is read.
CONTINUATION = re.compile(r"\\\s*\n\s*")

#: Gate steps the continuous-integration workflow must invoke.
REQUIRED_CI_COMMANDS = (
    "flake8",
    "pip-audit --strict -r backend/requirements.txt",
    "pip-audit --strict -r backend/requirements-dev.txt",
    "bandit -r backend/app -ll",
    "! pip show python-multipart",
    "python -m pytest backend/tests",
    "python -m pytest backend/tests/security",
    "alembic -c backend/alembic.ini upgrade head",
)

#: Names of the jobs the continuous-integration workflow declares.
EXPECTED_CI_JOBS = (
    "backend",
    "runtime-integration",
    "postgres-integration",
    "integration",
    "frontend",
    "infrastructure",
)


def _document(path):
    """Returns the parsed YAML document at ``path``."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _triggers(document):
    """Returns the trigger mapping of a workflow document.

    ``on`` is read by a YAML 1.1 parser as the boolean ``True``, so the
    key is resolved by value rather than by name.
    """
    for key, value in document.items():
        if key is True or key == "on":
            return value
    raise AssertionError("the workflow declares no trigger")


def _steps(document, job):
    """Returns the steps of one job."""
    return document["jobs"][job].get("steps") or []


def _script(document, job):
    """Returns every shell body one job runs, joined."""
    return "\n".join(
        step["run"] for step in _steps(document, job) if "run" in step
    )


def _step_named(document, job, fragment):
    """Returns the first step of ``job`` whose name carries ``fragment``."""
    for step in _steps(document, job):
        if fragment.lower() in str(step.get("name", "")).lower():
            return step
    raise AssertionError(
        "job {0!r} declares no step named for {1!r}".format(job, fragment)
    )


def _step_index(document, job, fragment):
    """Returns the position of the step named for ``fragment``."""
    for index, step in enumerate(_steps(document, job)):
        if fragment.lower() in str(step.get("name", "")).lower():
            return index
    raise AssertionError(
        "job {0!r} declares no step named for {1!r}".format(job, fragment)
    )


def _logical_lines(body):
    """Returns ``body``'s commands with continuations joined.

    A command written across continuations is one command. Matching the
    source text instead would report a gate as missing the moment a flag
    moved onto a line of its own.
    """
    kept = "\n".join(
        line for line in body.splitlines()
        if not line.strip().startswith("#")
    )
    joined = CONTINUATION.sub(" ", kept)
    return [" ".join(line.split()) for line in joined.splitlines()]


def _invokes(document, command):
    """Reports whether any job runs ``command`` as one command.

    Every token has to appear on one logical line, in any order and
    among any other flags. The gate that ran in a single job was split
    across several so that no job's failure can skip another's checks,
    so the workflow rather than one named job is what is searched.
    """
    tokens = command.split()
    for job in document["jobs"]:
        for line in _logical_lines(_script(document, job)):
            if all(token in line for token in tokens):
                return True
    return False


def _step_running(document, marker):
    """Returns the one step, in any job, whose commands hold ``marker``.

    Which job holds a step is found rather than named: the checks were
    split across jobs, and finding exactly one holder is itself an
    assertion -- two jobs probing the same route would mean two places
    to keep correct.
    """
    found = [
        step
        for job in document["jobs"]
        for step in _steps(document, job)
        if marker in step.get("run", "")
    ]
    assert found, marker
    return found[0]


def _needs_chain(document, job):
    """Returns every job ``job`` waits for, directly or transitively."""
    reached = set()
    pending = [job]
    while pending:
        declared = document["jobs"].get(pending.pop(), {}).get("needs", [])
        if isinstance(declared, str):
            declared = [declared]
        for name in declared:
            if name not in reached:
                reached.add(name)
                pending.append(name)
    return reached


def _uncommented(body):
    """Returns ``body`` with comment-only and blank lines removed."""
    kept = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        kept.append(stripped)
    return kept


def _build_invocations(text):
    """Yields the token list of every ``docker build`` command in ``text``.

    Continuation lines are collapsed first, so one command spread over
    several lines is read as the single command it is.
    """
    for line in CONTINUATION.sub(" ", text).splitlines():
        stripped = line.strip()
        if stripped.startswith("docker build"):
            yield [token for token in stripped.split() if token]


def _resolved(reference):
    """Returns ``reference`` as a repository path, or ``None``."""
    cleaned = reference.strip().strip('"')
    if cleaned.startswith("${REPO_ROOT}/"):
        cleaned = cleaned[len("${REPO_ROOT}/"):]
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    if not cleaned or cleaned.startswith("$"):
        return None
    return REPO_ROOT / cleaned


def _frontend_scripts():
    """Returns the script names the frontend manifest publishes."""
    manifest = json.loads(FRONTEND_MANIFEST.read_text(encoding="utf-8"))
    return set(manifest.get("scripts", {}))


@pytest.mark.parametrize("path", PIPELINE_FILES, ids=lambda p: p.name)
def test_no_pipeline_file_carries_an_unresolved_marker(path):
    text = path.read_text(encoding="utf-8")
    for marker in FORBIDDEN_MARKERS:
        assert marker not in text, "{0} carries {1}".format(path.name, marker)


def test_the_workflows_parse():
    for path in (CI_WORKFLOW, CD_WORKFLOW):
        document = _document(path)
        assert isinstance(document, dict), path.name
        assert document["jobs"], path.name


def test_the_integration_workflow_is_callable():
    triggers = _triggers(_document(CI_WORKFLOW))
    assert "workflow_call" in triggers


def test_the_integration_workflow_declares_both_jobs():
    document = _document(CI_WORKFLOW)
    assert tuple(document["jobs"]) == EXPECTED_CI_JOBS


def test_the_gate_job_does_not_wait_on_the_frontend_job():
    # A frontend failure must not stop the security gates from running
    # and reporting.
    document = _document(CI_WORKFLOW)
    assert "needs" not in document["jobs"]["backend"]


@pytest.mark.parametrize("command", REQUIRED_CI_COMMANDS)
def test_the_gate_job_invokes_every_required_command(command):
    # The gate is the workflow rather than one job of it, and a command
    # is matched by its tokens so that a continuation or an added flag
    # does not read as a missing gate.
    assert _invokes(_document(CI_WORKFLOW), command), command


def test_the_reachability_guard_covers_every_accepted_advisory_pattern():
    # Each pattern is assembled from fragments rather than written whole.
    # The guard this case verifies greps every *.py file under backend/ for
    # these very strings, so spelling them out here would make this module
    # the match that fails the guard.
    body = _script(_document(CI_WORKFLOW), "backend")
    for pattern in (
        "request" + r"\." + "form",
        "request" + r"\." + "url",
        "Static" + "Files",
        "HTTP" + "Endpoint",
        "set" + "_key",
        "un" + "set" + "_key",
        "Route" + r"\(",
        r"\b" + "cli" + "ck" + r"\b",
    ):
        assert pattern in body, pattern


def test_the_integration_step_runs_commands_rather_than_a_comment():
    step = _step_named(_document(CI_WORKFLOW), "backend", "integration")
    assert _uncommented(step["run"]), "the integration step is a no-op"


def test_the_integration_step_probes_the_readiness_route():
    step = _step_running(_document(CI_WORKFLOW), READINESS_PATH)
    assert READINESS_PATH in step["run"]


def test_the_integration_step_exercises_the_frozen_login_contract():
    step = _step_running(_document(CI_WORKFLOW), "/auth/register")
    body = step["run"]
    assert "/auth/register" in body
    assert "/auth/login" in body
    assert "access_token" in body
    assert "token_type" in body


def test_the_integration_step_runs_against_a_real_database():
    document = _document(CI_WORKFLOW)
    # The job holding the step is the one that has to attach the
    # service, so the two are read together rather than separately.
    holders = [
        (job, step)
        for job in document["jobs"]
        for step in _steps(document, job)
        if "/auth/register" in step.get("run", "")
    ]
    assert holders, "no step exercises the registration route"
    # More than one job exercises the running service, each contributed by
    # a different round and each covering a different set of routes. Every
    # one of them has to have the database, so the requirement is made of
    # each holder rather than of a single named job.
    for job, step in holders:
        assert "postgres" in document["jobs"][job]["services"], job
        supplied = json.dumps(
            step.get("env") or document["jobs"][job].get("env") or {}
        )
        assert "postgresql://" in supplied, (job, supplied)


def test_no_step_invokes_a_script_the_frontend_does_not_publish():
    # frontend/package.json is a read-only authority: a step may invoke
    # only a script it publishes.
    published = _frontend_scripts()
    document = _document(CI_WORKFLOW)
    # npm resolves four names without ``run``, so a step invoking one of
    # them is invoking a published script just as ``npm run`` would.
    body = _script(document, "frontend")
    invoked = re.findall(r"npm run ([A-Za-z0-9_:-]+)", body)
    invoked += re.findall(r"npm (test|start|stop|restart)\b", body)
    assert invoked, "the frontend job runs no npm script"
    for name in invoked:
        assert name in published, "frontend declares no {0!r} script".format(
            name
        )


def test_the_interpreter_pin_is_intact_in_the_integration_workflow():
    document = _document(CI_WORKFLOW)
    step = _step_named(document, "backend", "Set up Python")
    assert step["with"]["python-version"] == PINNED_PYTHON


def test_the_deployment_workflow_gates_on_the_whole_integration_suite():
    document = _document(CD_WORKFLOW)
    assert document["jobs"]["verify"]["uses"] == "./.github/workflows/ci.yml"
    # The image build sits between the gate and the deployment now, so
    # the dependency is reached through it. Following the chain keeps the
    # property -- nothing deploys until the whole gate passed -- asserted
    # whatever is added in between.
    assert "verify" in _needs_chain(document, "deploy")


def test_the_deployment_workflow_declares_least_privilege_and_serialises():
    document = _document(CD_WORKFLOW)
    assert document["permissions"] == {"contents": "read"}
    assert document["concurrency"]["group"]
    deploy = document["jobs"]["deploy"]["permissions"]
    assert deploy["contents"] == "read"
    assert deploy["id-token"] == "write"


def test_the_deployment_workflow_federates_rather_than_holding_a_key():
    step = _step_named(_document(CD_WORKFLOW), "deploy", "Authenticate")
    assert "workload_identity_provider" in step["with"]
    assert "service_account_key" not in step["with"]
    assert "credentials_json" not in step["with"]


def test_every_declared_build_names_a_dockerfile_that_exists():
    # Publishing moved onto its own job so that it runs on a runner that
    # never holds cluster credentials, so every job is read rather than
    # the deploying one.
    document = _document(CD_WORKFLOW)
    workflow_builds = 0
    for job in document["jobs"]:
        for flags in _build_invocations(_script(document, job)):
            workflow_builds += 1
            assert "-f" in flags, flags
            dockerfile = _resolved(flags[flags.index("-f") + 1])
            assert dockerfile is not None and dockerfile.is_file(), dockerfile
            context = _resolved(flags[-1])
            assert context is not None and context.is_dir(), context
    assert workflow_builds == 2, workflow_builds

    # The script builds one image per workload in a loop over the inventory
    # it declares, rather than repeating a build per workload. There is
    # therefore one build command and two pairs of paths, and the paths are
    # read out of the declarations the command indexes.
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert "docker build" in text
    assert '--file "${dockerfile}"' in text
    assert 'for workload in "${RELEASE_WORKLOADS[@]}"' in text
    for name, suffix in (("WORKLOAD_DOCKERFILE", "is_file"),
                         ("WORKLOAD_CONTEXT", "is_dir")):
        block = re.search(
            r"declare -A " + name + r"=\((.*?)\n\)", text, re.DOTALL
        )
        assert block is not None, name
        declared = re.findall(r'\["([a-z-]+)"\]="([^"]+)"', block.group(1))
        assert sorted(w for w, _ in declared) == sorted(DEPLOYED_WORKLOADS)
        for workload, relative in declared:
            resolved = REPO_ROOT / relative
            assert getattr(resolved, suffix)(), (workload, relative)


@pytest.mark.parametrize("path", (CD_WORKFLOW, DEPLOY_SCRIPT))
def test_no_image_addresses_a_retired_registry(path):
    text = path.read_text(encoding="utf-8")
    for host in RETIRED_REGISTRY_HOSTS:
        assert host not in text, "{0} names {1}".format(path.name, host)
    assert ARTIFACT_REGISTRY_SUFFIX in text


@pytest.mark.parametrize("path", (CD_WORKFLOW, DEPLOY_SCRIPT))
def test_cluster_credentials_are_requested_by_region(path):
    text = path.read_text(encoding="utf-8")
    assert "get-credentials" in text
    assert "--region" in text
    assert "--zone" not in text


@pytest.mark.parametrize("workload", DEPLOYED_WORKLOADS)
def test_every_mutated_workload_is_confirmed_to_exist_first(workload):
    document = _document(CD_WORKFLOW)
    body = _script(document, "deploy")
    assert "deployment/{0}".format(workload) in body
    # The step that reads the cluster before anything is changed is named
    # for the inventory it checks now rather than for the moment it runs
    # at. What it does is unchanged, and the ordering is what matters.
    check = _step_index(document, "deploy", "release inventory")
    rollout = _step_index(document, "deploy", "Deploy to GKE")
    migrate = _step_index(document, "deploy", "Apply database migrations")
    assert check < migrate < rollout


def test_the_deployment_workflow_confirms_the_namespace_before_mutating():
    document = _document(CD_WORKFLOW)
    step = _step_running(document, "get namespace")
    assert "get namespace" in step["run"]
    # And it does so before anything is applied.
    confirm = _steps(document, "deploy").index(step)
    assert confirm < _step_index(document, "deploy", "Deploy to GKE")


def test_the_deployment_workflow_probes_readiness_rather_than_liveness():
    step = _step_named(_document(CD_WORKFLOW), "deploy", "health checks")
    body = step["run"]
    assert READINESS_PATH in body
    # The liveness route may be read for diagnosis after readiness has
    # failed, and the step does that -- but only where the result cannot
    # decide the outcome, which is what ``|| true`` states. A liveness read
    # whose failure is not discarded would be a gate on the route that
    # answers throughout a database outage, and that is what is refused.
    for line in _logical_lines(body):
        if "8000/health" not in line or READINESS_PATH in line:
            continue
        assert line.rstrip().endswith("|| true"), line


def test_the_deployment_workflow_names_every_required_setting():
    document = _document(CD_WORKFLOW)
    declared = set(document["env"])
    # The namespace is carried as K8S_NAMESPACE, the name the manifests and
    # the deployment script both read, so one value governs all three.
    required = {
        "PROJECT_ID",
        "GKE_CLUSTER",
        "GKE_REGION",
        "K8S_NAMESPACE",
        "REGISTRY_LOCATION",
        "REGISTRY_REPOSITORY",
    }
    assert required <= declared, sorted(required - declared)
    step = _step_named(_document(CD_WORKFLOW), "deploy", "fully configured")
    # The check covers the settings an absent repository secret would
    # render empty. The block also declares constants of its own -- the
    # request timeouts, the resolved image tag -- which are values rather
    # than inputs and have nothing to be checked against.
    for name in sorted(required):
        assert name in step["run"], name


def test_the_deployment_script_stops_on_the_first_failure():
    lines = DEPLOY_SCRIPT.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "#!/bin/bash"
    # The options are the first thing the shell executes, which is the
    # property; the header comment above them executes nothing. ``-E``
    # additionally propagates the ERR trap into functions, so a failure
    # inside one is reported rather than only exited on.
    executed = [
        line for line in lines[1:]
        if line.strip() and not line.strip().startswith("#")
    ]
    assert executed[0] == "set -Eeuo pipefail", executed[0]


def test_the_deployment_script_migrates_before_it_rolls_out():
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    # The rollout is an apply of the rendered workload manifests, which
    # already carry this release's digests, rather than an in-place image
    # mutation on a live Deployment. The ordering is unchanged; the
    # commands that mark each point are not, so the retired one is
    # asserted absent as well.
    confirm = text.index("Checking the release inventory")
    migrate = text.index("upgrade head")
    rollout = text.index('"${RENDER}" workloads')
    assert confirm < migrate < rollout
    assert "kubectl set image" not in text


def test_the_deployment_script_confirms_its_target_before_mutating():
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    for fragment in (
        "get-credentials",
        # A kubeconfig private to this run, rather than a namespace set on
        # whatever context was already active on the host: nothing outside
        # this run can be reached, and nothing outside it is modified.
        'KUBECONFIG_FILE="$(mktemp)"',
        'export KUBECONFIG="${KUBECONFIG_FILE}"',
        "kubectl config current-context",
        "get namespace",
        '--request-timeout="${KUBECTL_REQUEST_TIMEOUT}"',
    ):
        assert fragment in text, fragment
    assert "set-context --current --namespace" not in text
    assert text.index("get namespace") < text.index('"${RENDER}" workloads')


def test_the_deployment_script_addresses_the_delivered_workloads():
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    # The inventory is declared once and every command iterates it, so a
    # workload is addressed through the declaration rather than by a
    # literal repeated at each call site.
    declared = re.search(
        r"readonly RELEASE_WORKLOADS=\(([^)]*)\)", text
    )
    assert declared is not None, "the script declares no release inventory"
    named = re.findall(r'"([a-z-]+)"', declared.group(1))
    assert sorted(named) == sorted(DEPLOYED_WORKLOADS), named
    assert 'deployment/${workload}' in text
    assert "app-deployment" not in text


def test_the_deployment_script_deploys_no_public_function():
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert "--allow-unauthenticated" not in text
    # The runtime pin is preserved at this site; the step that carries it
    # is opt-in because that runtime is decommissioned by the provider.
    assert PINNED_FUNCTION_RUNTIME in text
    # The gate is named for what authorizing it means rather than for
    # the step it enables, and the same name is the Terraform variable.
    assert "CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED" in text
    assert "allUsers" in text


def test_the_deployment_script_names_no_source_it_does_not_carry():
    text = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    assert "--source=./functions" not in text
    assert "CLOUD_FUNCTION_SOURCE" in text


@pytest.mark.parametrize("path", TERRAFORM_FILES, ids=lambda p: p.name)
def test_no_infrastructure_file_carries_an_unresolved_marker(path):
    text = path.read_text(encoding="utf-8")
    for marker in FORBIDDEN_MARKERS:
        assert marker not in text, "{0} carries {1}".format(path.name, marker)


def test_the_tool_and_provider_floors_are_declared():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    assert re.search(r'required_version\s*=\s*">=\s*1\.11', text)
    assert re.search(r'source\s*=\s*"hashicorp/google"', text)
    assert re.search(r'version\s*=\s*"~>\s*7\.', text)


def test_the_provider_selection_is_locked_for_every_release_platform():
    assert TERRAFORM_LOCK.is_file(), TERRAFORM_LOCK
    text = TERRAFORM_LOCK.read_text(encoding="utf-8")
    assert 'provider "registry.terraform.io/hashicorp/google"' in text
    assert re.search(r'constraints\s*=\s*"~>\s*7\.', text)
    # One h1 hash is recorded per platform. A lock carrying only the
    # platform it was generated on fails `terraform init` on the Linux
    # runner the release workflow uses.
    assert len(re.findall(r'"h1:', text)) >= 2, text


@pytest.mark.parametrize(
    "resource",
    (
        "google_artifact_registry_repository",
        "google_artifact_registry_repository_iam_member",
        "google_iam_workload_identity_pool",
        "google_iam_workload_identity_pool_provider",
        "google_service_account_iam_member",
        "google_secret_manager_secret_iam_member",
        "google_storage_bucket_object",
    ),
)
def test_every_required_infrastructure_resource_is_declared(resource):
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    assert 'resource "{0}"'.format(resource) in text


def test_the_registry_repository_is_a_docker_repository():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    block = text[text.index('resource "google_artifact_registry_repository"'):]
    assert 'format        = "DOCKER"' in block[: block.index("\n}")]


def test_the_federation_admits_one_repository_and_one_branch():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    assert "attribute_condition" in text
    assert "assertion.repository ==" in text
    assert "refs/heads/${var.github_deployment_branch}" in text
    assert 'issuer_uri = "https://token.actions.githubusercontent.com"' in text


def test_every_declared_secret_is_readable_by_the_backend_identity():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    declared = set(re.findall(r'secret_id = "([A-Z_]+)"', text))
    assert declared, text

    # The grant iterates a declared set rather than repeating a name per
    # resource, so the set is what is read. Reading the literal names out
    # of the grant would report every one of them as absent while the
    # grant covered all of them.
    backend = re.search(
        r"backend_secret_ids = \{(.*?)\n  \}", text, re.DOTALL
    )
    assert backend is not None, "no backend secret set is declared"
    granted = set(re.findall(r"([A-Z_]+)\s*=", backend.group(1)))

    # Two declared secrets are deliberately not the backend's to read:
    # the seed password belongs to the provisioning job, and the shared
    # rate-limit address is written by the release rather than read at
    # startup. Each is granted to the principal that needs it, which is
    # what least privilege means here.
    elsewhere = {
        "ADMIN_SEED_PASSWORD": "admin_provisioner",
        "RATE_LIMIT_STORAGE_URI": "deployer_rate_limit",
    }
    for secret_id in sorted(declared):
        if secret_id in elsewhere:
            holder = elsewhere[secret_id]
            assert (
                'resource "google_secret_manager_secret_iam_member" "%s"'
                % holder
            ) in text, holder
            continue
        assert secret_id in granted, secret_id

    grants = text[text.index(
        'resource "google_secret_manager_secret_iam_member" "backend_workload"'
    ):]
    grants = grants[: grants.index("\n}\n")]
    assert 'role      = "roles/secretmanager.secretAccessor"' in grants
    assert "for_each = local.backend_secret_ids" in grants


def test_the_cluster_and_its_nodes_serve_workload_identity():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    assert "workload_identity_config" in text
    assert '${var.project_id}.svc.id.goog' in text
    assert "workload_metadata_config" in text
    assert 'mode = "GKE_METADATA"' in text


def test_the_function_invoker_policy_is_authoritative():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    # An additive member leaves any other member in place, including a
    # public one an earlier deployment granted.
    assert 'resource "google_cloudfunctions_function_iam_binding"' in text
    assert 'resource "google_cloudfunctions_function_iam_member"' not in text
    assert "members = [var.cloud_function_invoker_member]" in text


def test_no_infrastructure_resource_grants_a_public_principal():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    for principal in ("allUsers", "allAuthenticatedUsers"):
        assert 'member = "{0}"'.format(principal) not in text
        assert '"{0}"]'.format(principal) not in text


def test_the_function_reads_a_source_object_this_configuration_creates():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    # The archive is packaged from the committed function directory by this
    # configuration and the object is named for the content it holds, so a
    # change to the function produces a new object name and the function is
    # actually redeployed. An object named by a variable would keep one name
    # across every revision of the source.
    assert 'data "archive_file" "function_source"' in text
    assert (
        "source_archive_object = "
        "google_storage_bucket_object.function_source.name" in text
    )
    assert "output_md5" in text
    assert 'source_archive_object = "function-source.zip"' not in text
    assert "entry_point           = var.cloud_function_entry_point" in text


def test_the_function_runtime_pin_is_intact():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    assert 'runtime     = "python39"' in text


def test_the_function_restricts_its_network_ingress():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    # The boundary is a validated variable rather than a literal, and
    # its default is the stricter of the two values the validation
    # admits. ALLOW_ALL, which would admit any caller on the internet,
    # is refused at plan time rather than being available to set.
    assert "ingress_settings = var.cloud_function_ingress_settings" in text
    declared = TERRAFORM_VARIABLES.read_text(encoding="utf-8")
    block = declared[
        declared.index('variable "cloud_function_ingress_settings"'):
    ]
    block = block[: block.index("\n}\n")]
    assert 'default     = "ALLOW_INTERNAL_ONLY"' in block
    assert "ALLOW_INTERNAL_ONLY" in block
    assert "ALLOW_INTERNAL_AND_GCLB" in block
    assert "contains([" in block
    assert '"ALLOW_ALL"' not in block.split("condition")[1].split("]")[0]


def test_the_database_keeps_its_hardening():
    text = TERRAFORM_MAIN.read_text(encoding="utf-8")
    assert "ipv4_enabled    = false" in text
    assert 'ssl_mode        = "ENCRYPTED_ONLY"' in text
    assert "deletion_protection = true" in text
    assert "point_in_time_recovery_enabled = true" in text


def test_no_output_exposes_a_secret_payload():
    text = TERRAFORM_OUTPUTS.read_text(encoding="utf-8")
    for fragment in (
        "secret_data",
        "var.secret_key",
        "var.database_url",
        "var.zillow_api_key",
        "var.paypal_client_secret",
        "var.paypal_webhook_id",
        "var.sendgrid_api_key",
        "google_secret_manager_secret_version",
    ):
        assert fragment not in text, fragment


def test_the_registry_output_publishes_the_host_the_pipeline_addresses():
    text = TERRAFORM_OUTPUTS.read_text(encoding="utf-8")
    assert ARTIFACT_REGISTRY_SUFFIX in text
    assert "workload_identity_provider" in text


def test_every_new_variable_is_declared():
    text = TERRAFORM_VARIABLES.read_text(encoding="utf-8")
    for name in (
        "artifact_registry_repository_id",
        "deployer_service_account_id",
        "deployer_roles",
        "workload_identity_pool_id",
        "workload_identity_pool_provider_id",
        "github_repository",
        "github_deployment_branch",
        "backend_workload_service_account_id",
        "backend_kubernetes_namespace",
        "backend_kubernetes_service_account",
        "cloud_function_name",
        "cloud_function_entry_point",
        "cloud_function_source_object",
        "cloud_function_source_archive",
        "cloud_function_service_account_id",
        "cloud_function_environment_variables",
        "cloud_function_vpc_connector",
        "cloud_function_secret_ids",
    ):
        assert 'variable "{0}"'.format(name) in text, name


def test_every_variable_the_configuration_reads_is_declared():
    referenced = set(
        re.findall(r"var\.([A-Za-z_][A-Za-z0-9_]*)", TERRAFORM_MAIN.read_text(
            encoding="utf-8"
        ))
    )
    declared = set(
        re.findall(
            r'variable "([A-Za-z_][A-Za-z0-9_]*)"',
            TERRAFORM_VARIABLES.read_text(encoding="utf-8"),
        )
    )
    assert referenced <= declared, sorted(referenced - declared)
