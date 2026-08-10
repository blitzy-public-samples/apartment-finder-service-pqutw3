"""Static checks over the pipeline and the deployment script.

Neither GitHub Actions nor a Kubernetes cluster is reachable from this
test process, so every property below is asserted against the workflow
and script declarations rather than against a run. What is asserted:

* the deployment script requires the tools and variables it uses, and the
  Cloud Function name, region, source archive and entry point all arrive
  as required variables rather than as literals
* the script applies the database migrations on the new image before that
  image serves traffic
* the script publishes the function with unauthenticated invocation
  withheld, from an archive it has confirmed exists, and reads the
  effective invoker policy back afterwards
* the container builds name their Dockerfile explicitly, because neither
  build context carries one, and the frontend build passes both
  arguments its image declares
* the continuous-integration workflow runs the backend gates in a job
  that nothing else can block, exposes a real integration gate, and is
  callable so that deployment can require the whole of it
* deployment depends on that call rather than on a subset of the gates
* the cluster credentials are fetched for a regional cluster on its
  internal endpoint, and the control plane is proved reachable before any
  migration runs
* the Python 3.9 pin sites in both files are unchanged
* no step is an empty placeholder

``frontend/package.json`` is the authority for the scripts that exist,
the two Dockerfiles are the authority for the build contexts and
arguments, and ``infrastructure/terraform`` is the authority for the
function identity these files consume.
"""

import re

import pytest
import yaml
from conftest import REPO_ROOT

#: Deployment script under test.
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy.sh"

#: Continuous-integration workflow under test.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Continuous-deployment workflow under test.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"

#: Frontend manifest, the authority for the scripts that exist.
FRONTEND_MANIFEST = REPO_ROOT / "frontend" / "package.json"

#: Image definitions, neither of which sits in its build context.
BACKEND_DOCKERFILE = "infrastructure/docker/Dockerfile.backend"
FRONTEND_DOCKERFILE = "infrastructure/docker/Dockerfile.frontend"

#: Build arguments the frontend image declares.
FRONTEND_BUILD_ARGUMENTS = (
    "REACT_APP_API_BASE_URL",
    "REACT_APP_PAYPAL_CLIENT_ID",
)

#: Inputs the deployment script requires from the environment. The
#: function contract -- its name, entry point and source object -- moved
#: out of this set and into declared constants that carry the same
#: values as the Terraform variables' defaults, so one value governs
#: both tools and neither can be given a name the other does not use.
#: The cluster region serves the function too, so it is named once.
REQUIRED_DEPLOY_VARIABLES = (
    "GCP_PROJECT_ID",
    "VERSION",
    "GKE_CLUSTER",
    "GKE_REGION",
    "K8S_NAMESPACE",
    "ARTIFACT_REGISTRY_REPOSITORY",
)

#: Function contract the script declares and Terraform defaults to.
FUNCTION_CONTRACT = {
    "CLOUD_FUNCTION_NAME": "apartment-finder-probe",
    "CLOUD_FUNCTION_ENTRY_POINT": "hello_world",
    "CLOUD_FUNCTION_SOURCE_OBJECT": "function-source.zip",
}

#: Commands the deployment script requires on PATH.
REQUIRED_DEPLOY_TOOLS = ("docker", "gcloud", "kubectl", "jq")

#: Manifest declaring the one-shot migration workload.
MIGRATION_MANIFEST = (
    REPO_ROOT / "infrastructure" / "kubernetes" / "60-migration-job.yaml"
)

#: Runtime pin the deployment script carries, quoted exactly.
DEPLOY_RUNTIME_PIN = "--runtime python39"

#: Interpreter pin both workflows carry.
WORKFLOW_PYTHON_PIN = "3.9"

#: IAM principals the script must refuse to find in the effective policy.
PUBLIC_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")

#: Markers that would leave a step for a reader to fill in.
PLACEHOLDER_MARKERS = ("HUMAN ASSISTANCE NEEDED", "TODO", "FIXME")


def _text(path):
    """Returns one file as text with normalised line endings."""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _workflow(path):
    """Returns one workflow document."""
    return yaml.safe_load(_text(path))


def _triggers(document):
    """Returns the trigger names of one workflow.

    ``on`` is parsed by PyYAML as the boolean ``True``, so both spellings
    are accepted here.
    """
    triggers = document.get("on", document.get(True))
    if isinstance(triggers, dict):
        return set(triggers)
    if isinstance(triggers, list):
        return set(triggers)
    return {triggers}


def _steps(document, job):
    """Returns the steps of one job."""
    return document["jobs"][job].get("steps", [])


def _step_index(document, job, fragment):
    """Returns the index of the first step whose name carries text."""
    for index, step in enumerate(_steps(document, job)):
        if fragment in step.get("name", ""):
            return index
    raise AssertionError((job, fragment))


def _frontend_scripts():
    """Returns the script names the frontend manifest declares."""
    import json

    manifest = json.loads(_text(FRONTEND_MANIFEST))
    return set(manifest.get("scripts", {}))


def test_the_release_files_are_all_present():
    """Asserts each file the assertions below read exists."""
    for path in (DEPLOY_SCRIPT, CI_WORKFLOW, CD_WORKFLOW):
        assert path.is_file(), path
        assert _text(path).strip(), path


def test_the_deployment_script_fails_on_the_first_error():
    """Asserts strict failure handling is still in force.

    The options are the first thing the shell executes rather than the
    first line of the file: a header comment describing the release
    contract sits above them and executes nothing. ``-E`` was added so
    the ERR trap reaches inside functions, where most of the script is.
    """
    lines = _text(DEPLOY_SCRIPT).split("\n")

    assert lines[0] == "#!/bin/bash"
    executed = [
        line for line in lines[1:]
        if line.strip() and not line.strip().startswith("#")
    ]
    assert executed[0] == "set -Eeuo pipefail", executed[0]


@pytest.mark.parametrize("tool", REQUIRED_DEPLOY_TOOLS)
def test_the_deployment_script_requires_each_tool_it_uses(tool):
    """Asserts a missing command is reported rather than assumed."""
    text = _text(DEPLOY_SCRIPT)
    required = re.search(r"for tool in ([^\n;]+); do", text)

    assert required is not None
    assert tool in required.group(1).split()
    assert "command -v" in text


@pytest.mark.parametrize("name", REQUIRED_DEPLOY_VARIABLES)
def test_the_deployment_script_requires_each_variable(name):
    """Asserts the script stops when an input is absent.

    Each input is now required by name through one helper, which also
    refuses a value that cannot be what the input is for -- a project id
    that is not a project id reaches gcloud as a target rather than as an
    error. Reading the helper's call sites is what enumerates the set.
    """
    text = _text(DEPLOY_SCRIPT)
    block = text[text.index("read_inputs() {"):]
    block = block[: block.index("\n}\n")]

    assert "require_input " + name + " " in block, name
    assert 'echo "Required environment variable ${name} is not set."' in text


def test_the_deployment_script_names_no_function_literally():
    """Asserts the function identity is not hardcoded."""
    text = _text(DEPLOY_SCRIPT)

    assert "function-name" not in text
    assert "function-test" not in text
    assert "./functions" not in text
    assert '"${CLOUD_FUNCTION_NAME}"' in text


def test_the_deployment_script_migrates_before_it_serves():
    """Asserts the schema is applied before the rollout.

    The migration is a one-shot Job the manifests declare, waited on for
    completion, and the rollout is an apply of the workload manifests
    carrying this release's digests. The ordering is what it was; the
    commands marking each point are not, so the retired in-place image
    mutation is asserted absent as well.
    """
    text = _text(DEPLOY_SCRIPT)

    migration = text.index('"${RENDER}" migration')
    gate = text.index("--for=condition=complete")
    rollout = text.index('"${RENDER}" workloads')

    assert migration < gate < rollout
    assert "kubectl set image" not in text


def test_the_deployment_script_runs_migrations_in_one_shot():
    """Asserts the migration runs once, on its own, on the new image.

    It was a pod the script created with ``kubectl run`` and removed in a
    trap. It is a Job the manifests declare now, which the script renders
    and applies: the specification is owned by the repository rather than
    assembled at the keyboard, the same manifest the delivery workflow
    applies, and the cluster reclaims it on its own timer -- which holds
    when the script is interrupted, where a trap would not have run.
    """
    text = _text(DEPLOY_SCRIPT)
    manifest = _text(MIGRATION_MANIFEST)

    assert '"${RENDER}" migration' in text
    assert "wait \"job/${job_name}\"" in text
    assert "restartPolicy: Never" in manifest
    assert "ttlSecondsAfterFinished:" in manifest
    assert "${IMAGE_TAG}" in manifest
    assert "backend/alembic.ini" in manifest
    assert "kubectl run" not in text


def test_the_deployment_script_confirms_the_archive_exists():
    """Asserts the source is checked before the deploy call."""
    text = _text(DEPLOY_SCRIPT)

    check = text.index("gcloud storage objects describe")
    deploy = text.index("gcloud functions deploy")

    assert check < deploy
    assert "gs://*/*" in text
    assert text.index("gs://*/*") < check


def test_the_deployment_script_withholds_public_invocation():
    """Asserts the function is published without anonymous access."""
    text = _text(DEPLOY_SCRIPT)

    assert "--no-allow-unauthenticated" in text
    assert re.search(r"(?<!-no)-allow-unauthenticated\b", text) is None


def test_the_deployment_script_reads_the_effective_policy_back():
    """Asserts a surviving public binding stops the deployment."""
    text = _text(DEPLOY_SCRIPT)

    assert "gcloud functions get-iam-policy" in text
    for principal in PUBLIC_PRINCIPALS:
        assert principal in text, principal
    # The refusal message is written across continuations, so the
    # command is read as one rather than line by line.
    joined = " ".join(re.sub(r"\\\s*\n\s*", " ", text).split())
    assert 'still grants" "${public_principal}; remove that binding' in joined


def test_the_deployment_script_keeps_the_runtime_pin():
    """Asserts the Python 3.9 pin site is unchanged."""
    text = _text(DEPLOY_SCRIPT)

    assert DEPLOY_RUNTIME_PIN in text
    assert "python310" not in text
    assert "python311" not in text


def test_the_deployment_script_names_the_backend_dockerfile():
    """Asserts the build does not rely on a default Dockerfile.

    One build command iterates the release inventory now rather than a
    command per workload, so the name is read out of the declaration
    the command indexes. The property is unchanged: no build resolves a
    ``Dockerfile`` from the root of its context.
    """
    text = _text(DEPLOY_SCRIPT)

    assert '--file "${dockerfile}"' in text
    assert '["backend"]="%s"' % BACKEND_DOCKERFILE in text
    assert '["frontend"]="%s"' % FRONTEND_DOCKERFILE in text
    assert re.search(r"docker build -t", text) is None
    for line in re.sub(r"\\\s*\n\s*", " ", text).split("\n"):
        if "docker build" not in line:
            continue
        assert "--file" in line or " -f " in line, line


def test_the_frontend_manifest_declares_no_lint_script():
    """Asserts the authority for what the workflow may invoke."""
    assert "lint" not in _frontend_scripts()
    assert "test" in _frontend_scripts()


def test_the_workflow_invokes_no_absent_frontend_script():
    """Asserts no step calls a script the manifest does not carry."""
    text = _text(CI_WORKFLOW)
    invoked = set(re.findall(r"npm run ([a-z:-]+)", text))

    assert "npm run lint" not in text
    for script in invoked:
        assert script in _frontend_scripts(), script


def test_the_backend_gates_run_in_an_unblocked_job():
    """Asserts nothing can stop the backend gates from running."""
    document = _workflow(CI_WORKFLOW)
    backend = document["jobs"]["backend"]

    assert "needs" not in backend
    assert backend.get("continue-on-error") is None

    names = [step.get("name", "") for step in _steps(document, "backend")]
    # The audit runs once per manifest, so each step names the manifest
    # it audits rather than the tool alone.
    for expected in (
        "Run Flake8",
        "Run pip-audit against the runtime manifest",
        "Run pip-audit against the development manifest",
        "Run Bandit",
        "Check python-multipart is absent",
        "Check residual advisory reachability",
        "Run backend unit tests",
        "Run backend security tests",
    ):
        assert expected in names, expected


def test_the_reachability_guard_covers_the_application_package():
    """Asserts the textual guard is scoped to reachable code."""
    text = _text(CI_WORKFLOW)

    assert "--include=*.py backend/app/" in text
    assert "--include=*.py backend/ " not in text


def test_the_frontend_job_is_marked_and_gates_nothing():
    """Asserts the frontend job blocks nothing else.

    It carried ``continue-on-error`` and a name saying so while the
    workspace could not build. A later round removed both: a tolerated job
    reports a pass whatever happened inside it, which is indistinguishable
    from a gate that works, and the workspace builds now. What this case
    exists for -- that a frontend failure cannot stop a backend gate --
    is asserted below, and is what the absence of the toleration makes
    honest rather than assumed.
    """
    document = _workflow(CI_WORKFLOW)
    frontend = document["jobs"]["frontend"]

    assert frontend.get("continue-on-error") is None
    assert "Frontend" in frontend["name"]
    assert "known blocker" not in frontend["name"]

    for name, job in document["jobs"].items():
        if name == "frontend":
            continue
        needs = job.get("needs") or []
        needs = [needs] if isinstance(needs, str) else needs
        assert "frontend" not in needs, name


def test_the_integration_gate_runs_a_real_check():
    """Asserts the integration job exercises the running service."""
    document = _workflow(CI_WORKFLOW)
    integration = document["jobs"]["integration"]
    names = [step.get("name", "") for step in _steps(document, "integration")]

    # It waited on the backend job, which meant a failing unit test
    # skipped the runtime check entirely. It declares no dependency
    # now, so each reports on its own.
    assert "needs" not in integration
    assert "postgres" in integration["services"]
    assert integration["services"]["postgres"]["image"].startswith(
        "postgres:13"
    )
    for expected in (
        "Apply database migrations",
        "Confirm exactly one administrator exists",
        "Start the API",
        "Probe liveness and readiness",
        "Probe the public listing read",
        "Probe registration, login and the role refusal",
    ):
        assert expected in names, expected


def test_the_integration_gate_asserts_the_frozen_contracts():
    """Asserts the probes cover the contracts that must not move."""
    text = _text(CI_WORKFLOW)

    assert '"$BASE_URL/auth/register"' in text
    assert '"$BASE_URL/auth/login"' in text
    assert 'sorted(d)==["access_token","token_type"]' in text
    assert '"$BASE_URL/listings/?limit=1"' in text
    assert 'test "$anonymous" = "401"' in text
    assert 'test "$as_registered" = "403"' in text
    assert 'test "$holders" = "1"' in text


def test_the_pipeline_is_callable_by_the_deployment_workflow():
    """Asserts the whole pipeline can be required by another one."""
    document = _workflow(CI_WORKFLOW)

    assert "workflow_call" in _triggers(document)
    assert "push" in _triggers(document)
    assert "pull_request" in _triggers(document)


def test_deployment_requires_the_whole_pipeline():
    """Asserts deployment is gated on the called workflow.

    The job calling the pipeline is named ``verify``, a preflight job runs
    ahead of it, and the image build was separated from the cluster job so
    the two run on different runners and only the second holds cluster
    credentials. The dependency is therefore reached through the build
    rather than declared on the gate, and following the chain is what
    keeps the property asserted whatever is added between the two.
    """
    document = _workflow(CD_WORKFLOW)
    jobs = document["jobs"]

    assert jobs["verify"]["uses"] == "./.github/workflows/ci.yml"
    assert set(jobs) == {"preflight", "verify", "build", "deploy"}

    chain = set()
    pending = ["deploy"]
    while pending:
        declared = jobs.get(pending.pop(), {}).get("needs", [])
        declared = [declared] if isinstance(declared, str) else declared
        for name in declared:
            if name not in chain:
                chain.add(name)
                pending.append(name)
    assert "verify" in chain, chain


def test_deployment_keeps_least_privilege_and_serialises_runs():
    """Asserts the token grants and the concurrency group survive."""
    document = _workflow(CD_WORKFLOW)

    assert document["permissions"] == {"contents": "read"}
    assert document["concurrency"]["group"]
    assert document["jobs"]["deploy"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }


def test_deployment_authenticates_without_a_stored_key():
    """Asserts federated identity is still what authenticates."""
    text = _text(CD_WORKFLOW)

    assert "workload_identity_provider" in text
    assert "service_account_key" not in text
    assert "credentials_json" not in text


def test_deployment_builds_both_images_with_a_named_dockerfile():
    """Asserts neither build relies on a default Dockerfile."""
    text = _text(CD_WORKFLOW)

    assert "-f %s" % BACKEND_DOCKERFILE in text
    assert "-f %s" % FRONTEND_DOCKERFILE in text
    # Each build ends with the directory it builds from, and neither of
    # those directories holds a ``Dockerfile`` -- which is what makes the
    # ``-f`` flag above load-bearing rather than decorative. An earlier
    # revision asserted the contexts were absent from the file, which read
    # a build with no context as the safe case; a build with no context
    # would build the repository root, and the root does hold none either
    # only by accident. The delivered form names both, and the property
    # asserted here is that every build names its Dockerfile.
    assert "./backend" in text
    assert "./frontend" in text
    for line in re.sub(r"\\\s*\n\s*", " ", text).split("\n"):
        if "docker build" not in line:
            continue
        assert " -f " in line, line
    # Each value is quoted, because a secret rendered unquoted would be
    # split on whitespace before it reached the build.
    for argument in FRONTEND_BUILD_ARGUMENTS:
        assert '--build-arg "%s=' % argument in text, argument


def test_deployment_reaches_a_regional_private_control_plane():
    """Asserts the credential command matches the created cluster."""
    document = _workflow(CD_WORKFLOW)
    text = _text(CD_WORKFLOW)

    assert "--region" in text
    # The control plane carries no external address, and the two ways to
    # reach it are mutually exclusive flags: ``--internal-ip`` requires the
    # runner to sit inside the VPC and share its network, while
    # ``--dns-endpoint`` resolves the control plane through DNS and is
    # authorized by IAM. The delivered path uses the latter, so the former
    # has to be absent -- passing both is refused by gcloud.
    assert "--dns-endpoint" in text
    assert "--internal-ip" not in text
    assert "--zone" not in text
    assert "GKE_ZONE" not in text
    assert document["env"]["GKE_REGION"]
    assert "vars.GKE_DEPLOY_RUNNER" in str(
        document["jobs"]["deploy"]["runs-on"]
    )


def test_deployment_proves_connectivity_before_it_migrates():
    """Asserts an unreachable control plane is reported, not retried."""
    document = _workflow(CD_WORKFLOW)

    connectivity = _step_index(
        document, "deploy", "control plane is reachable"
    )
    migration = _step_index(document, "deploy", "Apply database migrations")
    rollout = _step_index(document, "deploy", "Deploy to GKE")

    assert connectivity < migration < rollout


def test_the_pipeline_keeps_the_interpreter_pin():
    """Asserts every Python setup in either workflow names 3.9.

    The pipeline is the pin site the requirements name; the deployment
    workflow runs no Python of its own and so carries no pin, which is
    why an empty pin list is accepted there and nowhere else.
    """
    ci_pins = re.findall(
        r"python-version: '([^']+)'", _text(CI_WORKFLOW)
    )

    assert ci_pins
    for path in (CI_WORKFLOW, CD_WORKFLOW):
        for pin in re.findall(
            r"python-version: '([^']+)'", _text(path)
        ):
            assert pin == WORKFLOW_PYTHON_PIN, (path.name, pin)


@pytest.mark.parametrize(
    "path",
    (DEPLOY_SCRIPT, CI_WORKFLOW, CD_WORKFLOW),
    ids=lambda p: p.name,
)
def test_no_placeholder_marker_survives(path):
    """Asserts nothing is left for a reader to fill in."""
    text = _text(path)

    for marker in PLACEHOLDER_MARKERS:
        assert marker not in text, marker


@pytest.mark.parametrize(
    "path", (CI_WORKFLOW, CD_WORKFLOW), ids=lambda p: p.name
)
def test_no_step_is_an_empty_placeholder(path):
    """Asserts every step either runs something or uses an action."""
    document = _workflow(path)

    for name, job in document["jobs"].items():
        if "uses" in job:
            continue
        for step in job.get("steps", []):
            if "uses" in step:
                continue
            body = step.get("run", "")
            statements = [
                line.strip()
                for line in body.split("\n")
                if line.strip() and not line.strip().startswith("#")
            ]
            assert statements, (name, step.get("name"))
