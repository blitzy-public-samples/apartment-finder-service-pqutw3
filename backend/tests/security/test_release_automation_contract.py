"""Checks over the release automation this repository ships.

``scripts/deploy.sh``, ``.github/workflows/cd.yml`` and
``.github/workflows/ci.yml`` are the only paths that reach a cluster, a
registry or a deployed function, and none of them can be exercised
against Google Cloud from a test. What is asserted here is therefore the
part that is checkable without a cloud: the declarations each path
carries, the agreement between them and
``infrastructure/terraform/main.tf``, and the behaviour of the release
script's own argument and input handling, which runs to completion
without contacting anything.

Three groups of cases live here.

* **Release script behaviour.** The script is executed, with a directory
  of inert stand-ins ahead of it on ``PATH`` so that no real ``gcloud``,
  ``kubectl`` or ``docker`` is reachable. Argument rejection and input
  validation both complete before any of those stand-ins is called, so
  these cases observe real exit statuses and change nothing.
* **Release script declarations.** Static assertions over the script's
  source: the inventory it addresses, the registry host it publishes to,
  how it addresses the cluster, the order of its steps, and the bounds
  and scoping every external command carries.
* **Cross-path agreement.** One release inventory, one registry, one
  Cloud Function contract and one advisory register across the script,
  both workflows and the Terraform configuration.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import os
import re
import shutil
import stat
import subprocess

import pytest
import yaml
from conftest import REPO_ROOT

#: Release script under test.
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy.sh"

#: Workflow that releases on a push to the default branch.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"

#: Workflow that gates a change before it can be released.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Terraform configuration that owns the cluster, the registry, the
#: secrets and the Cloud Function.
TERRAFORM_MAIN = (
    REPO_ROOT / "infrastructure" / "terraform" / "main.tf"
)

#: Deployments the release publishes. Each one runs a single container of
#: the same name, and each image is published under a repository of that
#: name.
RELEASE_WORKLOADS = ("backend", "frontend")

#: Image definition and build context per workload, relative to the
#: repository root. Both are the values Compose builds that image from.
WORKLOAD_BUILD = {
    "backend": (
        "infrastructure/docker/Dockerfile.backend",
        "backend",
    ),
    "frontend": (
        "infrastructure/docker/Dockerfile.frontend",
        "frontend",
    ),
}

#: Registry host suffix every published image carries. Container
#: Registry was shut down for writes, so no release path may publish to
#: it.
ARTIFACT_REGISTRY_SUFFIX = "-docker.pkg.dev"

#: Registry host no release path may publish to.
RETIRED_REGISTRY_HOST = "gcr.io"

#: Cloud Function contract. Every value is shared by the release script
#: and the Terraform resource, and the runtime is pinned.
#: Function name Terraform defaults to and the release script declares.
#: It read ``function-test`` while that generic value was the default;
#: a later round replaced it, on the ground that a generic placeholder
#: in executable infrastructure is indistinguishable from a real
#: configuration until an apply produces something nobody wanted.
CLOUD_FUNCTION_NAME = "apartment-finder-probe"
CLOUD_FUNCTION_ENTRY_POINT = "hello_world"
PINNED_FUNCTION_RUNTIME = "python39"

#: Terraform outputs carrying the identity of the one source archive the
#: configuration publishes. The release script reads both under the same
#: names, so the object it deploys is the object Terraform built rather
#: than whatever currently answers to a fixed name.
FUNCTION_SOURCE_OUTPUTS = (
    "cloud_function_source_object",
    "cloud_function_source_md5",
)

#: Names the release script must no longer hold as constants. A source
#: object named after its content digest changes whenever the bytes do, so
#: a constant here could only ever be one of the two out of step.
RETIRED_FUNCTION_CONSTANTS = ("CLOUD_FUNCTION_SOURCE_OBJECT",)

#: Stand-ins placed ahead of the real tools on ``PATH``. Each one exits
#: zero and does nothing, so a case that reaches one of them fails on the
#: assertion rather than by contacting Google Cloud.
INERT_TOOLS = ("gcloud", "kubectl", "docker", "jq", "timeout")

#: Body of one stand-in.
INERT_TOOL_BODY = "#!/bin/sh\nexit 0\n"

#: Seconds any executed case is allowed.
EXECUTION_TIMEOUT_SECONDS = 60

#: Shell options every command-bearing block of the release workflow
#: opens with, so a failing command inside a block ends the step.
STRICT_SHELL_OPTIONS = "set -euo pipefail"

#: Advisory identifiers each audit gate suppresses, per manifest. Both
#: workflows suppress the same sets, and every identifier is registered
#: in docs/security/RESIDUAL_RISK.md.
RUNTIME_SUPPRESSIONS = (
    "PYSEC-2026-161",
    "PYSEC-2026-248",
    "PYSEC-2026-249",
    "PYSEC-2026-2280",
    "PYSEC-2026-2281",
    "PYSEC-2026-2270",
    "PYSEC-2026-2132",
)
DEVELOPMENT_SUPPRESSIONS = ("PYSEC-2026-1845",)

#: Identifiers the development gate suppressed while the audit instrument
#: was declared in the manifest it audits. The instrument now has its own
#: manifest, which no audit reads, so each of these is neither reported nor
#: suppressed. None may return to an ignore list.
WITHDRAWN_DEVELOPMENT_SUPPRESSIONS = (
    "PYSEC-2026-3625",
    "PYSEC-2026-1374",
    "PYSEC-2026-1375",
    "PYSEC-2026-2275",
    "PYSEC-2026-141",
    "PYSEC-2026-142",
)

#: Manifest declaring the audit instrument, which is installed by the gate
#: and audited by neither invocation.
AUDIT_MANIFEST = "backend/requirements-audit.txt"

#: Register that has to account for every suppressed identifier above.
RESIDUAL_RISK_REGISTER = (
    REPO_ROOT / "docs" / "security" / "RESIDUAL_RISK.md"
)

#: Log that carries the reasoning the register defers to.
DECISION_LOG = REPO_ROOT / "docs" / "security" / "DECISION_LOG.md"

#: Development manifest, which now defers to that register instead of
#: carrying the argument for its own accepted set.
DEVELOPMENT_MANIFEST = REPO_ROOT / "backend" / "requirements-dev.txt"

#: Heading opening the section that accounts for each manifest.
REGISTER_HEADINGS = {
    "backend/requirements.txt": (
        "## Runtime register: seven accepted runtime advisories"
    ),
    "backend/requirements-dev.txt": (
        "## Development register: "
        "one accepted development advisory"
    ),
}

#: Every identifier suppressed across both audit invocations.
TOTAL_SUPPRESSIONS = len(RUNTIME_SUPPRESSIONS) + len(
    DEVELOPMENT_SUPPRESSIONS
)

#: Documents that quote an accepted-advisory figure to a reader, with
#: the wording each one used while it advertised the runtime seven as
#: the whole. None may return.
ADVERTISED_FIGURES = {
    "SECURITY.md": (
        "Seven advisories across three packages are currently accepted",
    ),
    "README.md": (
        "**Only** the seven documented residual advisories",
        "No advisory outside the set documented in that manifest's "
        "header",
    ),
    "blitzy-deck/executive-summary.html": (
        "Seven dependency advisories are accepted as residual risk.",
    ),
}

#: Interpreter the pin holds every workflow to.
PINNED_INTERPRETER = "3.9"

#: One suppressed advisory identifier on an audit command line.
IGNORED_ADVISORY = re.compile(r"--ignore-vuln\s+(PYSEC-[0-9-]+)")

#: Status the script exits with when it is given an argument.
USAGE_STATUS = 2

#: Inputs that satisfy every pattern the script applies.
ACCEPTED_INPUTS = {
    "GCP_PROJECT_ID": "my-project",
    "GKE_CLUSTER": "primary-cluster",
    "GKE_REGION": "us-central1",
    "K8S_NAMESPACE": "default",
    "VERSION": "2026.08.09-1",
}

#: One ``readonly`` assignment of a capitalised name, unquoted.
READONLY_VALUE = re.compile(
    r'(?m)^\s*readonly\s+([A-Z][A-Z0-9_]*)="?([^"\n]*)"?\s*$'
)

#: One entry of a declared associative array.
ARRAY_ENTRY = re.compile(r'\["(?P<key>[^"]+)"\]="(?P<value>[^"]*)"')

#: Delimiter of the here-document the usage text lives in.
USAGE_DELIMITER = "USAGE"


def _script_text():
    """Returns the release script exactly as it is committed."""
    return DEPLOY_SCRIPT.read_text(encoding="utf-8")


def _workflow(path):
    """Returns one parsed workflow document."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _workflow_text(path):
    """Returns one workflow as text."""
    return path.read_text(encoding="utf-8")


def _terraform_text():
    """Returns the Terraform configuration as text."""
    return TERRAFORM_MAIN.read_text(encoding="utf-8")


def _variables_text():
    """Returns the Terraform variable declarations as text."""
    return (TERRAFORM_MAIN.parent / "variables.tf").read_text(
        encoding="utf-8"
    )


def _outputs_text():
    """Returns the Terraform outputs as text."""
    return (TERRAFORM_MAIN.parent / "outputs.tf").read_text(
        encoding="utf-8"
    )


def _variable_default(name):
    """Returns the default one Terraform variable declares."""
    block = _variables_text().split('variable "' + name + '"')
    assert len(block) == 2, "no variable named " + name
    found = re.search(
        r'(?m)^\s*default\s*=\s*"([^"\n]*)"\s*$',
        block[1].split('\nvariable "')[0],
    )
    assert found is not None, name + " declares no string default"
    return found.group(1)


def _constant(name):
    """Returns the value the release script freezes for ``name``."""
    for found, value in READONLY_VALUE.findall(_script_text()):
        if found == name:
            return value
    raise AssertionError("the script declares no " + name)


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


def _inert_path(directory):
    """Writes the stand-ins and returns a ``PATH`` that finds them first.

    Every tool the script requires is present and inert, so the script
    passes its own prerequisite check and then fails, or succeeds, on its
    own argument and input handling alone.
    """
    binaries = directory / "bin"
    binaries.mkdir()

    for tool in INERT_TOOLS:
        executable = binaries / tool
        executable.write_text(INERT_TOOL_BODY, encoding="utf-8")
        executable.chmod(executable.stat().st_mode | stat.S_IEXEC)

    return str(binaries) + os.pathsep + os.environ.get("PATH", "")


def _run_script(tmp_path, arguments=(), inputs=None):
    """Runs the release script and returns the completed process."""
    environment = dict(os.environ)
    environment["PATH"] = _inert_path(tmp_path)
    environment.pop("KUBECONFIG", None)

    for name in ACCEPTED_INPUTS:
        environment.pop(name, None)

    if inputs:
        environment.update(inputs)

    return subprocess.run(
        [_bash(), str(DEPLOY_SCRIPT)] + list(arguments),
        cwd=str(tmp_path),
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=EXECUTION_TIMEOUT_SECONDS,
    )


def _executable_lines():
    """Returns the script's logical lines that run something.

    Continued lines are joined, so a flag carried on the second line of a
    command is read as part of that command. Comments and the usage
    here-document are dropped, so a tool named in prose is not read as an
    invocation of it.
    """
    text = _script_text().replace("\r\n", "\n").replace("\\\n", " ")
    lines = []
    inside_usage = False

    for raw in text.split("\n"):
        line = " ".join(raw.split())

        if inside_usage:
            inside_usage = line != USAGE_DELIMITER
            continue

        if "<<'" + USAGE_DELIMITER + "'" in line:
            inside_usage = True
            continue

        if not line or line.startswith("#"):
            continue

        lines.append(line)

    return lines


def _migration_manifest_text():
    """Returns the manifest declaring the one-shot migration workload."""
    return (
        REPO_ROOT / "infrastructure" / "kubernetes"
        / "60-migration-job.yaml"
    ).read_text(encoding="utf-8")


def _steps(path, job):
    """Returns one job's steps, in the order the workflow runs them.

    A job that calls a reusable workflow declares no steps of its own,
    which is what makes the call the whole of the gate rather than a
    restatement of part of it.
    """
    return _workflow(path)["jobs"][job].get("steps", [])


def _step(path, job, name):
    """Returns one named step of one job.

    Publishing was separated from the cluster job so the two run on
    different runners and only the second holds cluster credentials, so
    a step named here may sit in a neighbouring job. It is found
    wherever it is declared, and the job it was expected in is reported
    if it is nowhere.
    """
    for step in _steps(path, job):
        if step.get("name") == name:
            return step
    for other in _workflow(path)["jobs"]:
        for step in _steps(path, other):
            if step.get("name") == name:
                return step
    raise AssertionError("no step named " + name + " in " + job)


def _step_running(path, command):
    """Returns the one step of one workflow that runs ``command``.

    A step is named by whoever wrote it and renamed by whoever splits it,
    so a step is found here by the work it does. Exactly one step may run
    the command: two would be two places to keep in step with each other.
    """
    found = [
        step
        for job in _workflow(path)["jobs"]
        for step in _steps(path, job)
        if command in (step.get("run") or "")
    ]

    assert len(found) == 1, [step.get("name") for step in found]

    return found[0]


def _step_names(path, job):
    """Returns the names of one job's steps, in order."""
    return [step.get("name") for step in _steps(path, job)]


def _run_blocks(path):
    """Returns every command-bearing block of one workflow."""
    blocks = []
    for job, definition in _workflow(path)["jobs"].items():
        for step in definition.get("steps", []):
            if "run" in step:
                blocks.append((job, step.get("name"), step["run"]))
    return blocks


def _suppressed(path, manifest):
    """Returns the advisories one workflow suppresses for a manifest."""
    for _job, _name, block in _run_blocks(path):
        if "pip-audit" not in block:
            continue
        for command in block.split("pip-audit")[1:]:
            if manifest in command.split("\n")[0]:
                return tuple(IGNORED_ADVISORY.findall(command))
    raise AssertionError("no audit of " + manifest + " in " + str(path))


def _statements(name):
    """Returns every invocation of ``name``, without its own word.

    The prerequisite loop names every required tool in one list rather
    than invoking any of them, so a line introducing a loop is not read
    as an invocation.
    """
    invocation = re.compile(r"(?<![\w.-])" + name + r"(?=\s)")
    found = []

    for line in _executable_lines():
        if line.startswith("for "):
            continue

        match = invocation.search(line)

        if match is not None:
            found.append(line[match.end():].strip())

    return found


def test_the_release_script_parses():
    """``bash -n`` accepts the script."""
    completed = subprocess.run(
        [_bash(), "-n", str(DEPLOY_SCRIPT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=EXECUTION_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", "replace"
    )


def test_the_release_script_reports_no_shellcheck_finding():
    """ShellCheck reports nothing, so no expansion is left unquoted.

    The committed file may carry either line ending, and a carriage
    return is a finding of its own, so the source is normalised before it
    is analysed.
    """
    shellcheck = shutil.which("shellcheck")
    if shellcheck is None:
        pytest.skip("shellcheck is unavailable on this host")

    completed = subprocess.run(
        [shellcheck, "--format=gcc", "--shell=bash", "-"],
        input=_script_text().replace("\r\n", "\n").encode("utf-8"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=EXECUTION_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stdout.decode(
        "utf-8", "replace"
    )


def test_the_release_script_prints_its_usage_and_exits_zero(tmp_path):
    """``--help`` documents every input and changes nothing."""
    completed = _run_script(tmp_path, arguments=("--help",))
    printed = completed.stdout.decode("utf-8", "replace")

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", "replace"
    )

    for name in ACCEPTED_INPUTS:
        assert name in printed, name


def test_the_release_script_refuses_a_positional_argument(tmp_path):
    """An argument is refused before any step is reached.

    The previous form of this script took none and ignored any it was
    given, so a mistyped invocation could still authenticate and mutate.
    """
    completed = _run_script(tmp_path, arguments=("production",))

    assert completed.returncode == USAGE_STATUS
    assert b"production" in completed.stderr


@pytest.mark.parametrize("absent", sorted(ACCEPTED_INPUTS))
def test_the_release_script_refuses_an_absent_required_input(
    tmp_path, absent
):
    """Every input in the release tuple is required, not defaulted."""
    supplied = dict(ACCEPTED_INPUTS)
    del supplied[absent]

    completed = _run_script(tmp_path, inputs=supplied)

    assert completed.returncode != 0
    assert absent.encode("utf-8") in completed.stderr


@pytest.mark.parametrize(
    "name,rejected",
    [
        ("GCP_PROJECT_ID", "Bad Project"),
        ("GCP_PROJECT_ID", "-leading-hyphen"),
        ("GKE_CLUSTER", "Primary_Cluster"),
        ("GKE_REGION", "us-central1-a"),
        ("K8S_NAMESPACE", "Default"),
        ("K8S_NAMESPACE", "default\nevil"),
        ("VERSION", "--force"),
        ("VERSION", "tag with spaces"),
        ("ARTIFACT_REGISTRY_REPOSITORY", "Repo/Nested"),
    ],
)
def test_the_release_script_refuses_a_malformed_input(
    tmp_path, name, rejected
):
    """A malformed input is refused rather than reaching a command line.

    The zone case matters on its own: the cluster is regional, so a zone
    supplied where a region belongs is a value the cluster cannot be
    addressed by. The newline case matters because a value carrying one
    could otherwise be partly matched by a line-oriented check.
    """
    supplied = dict(ACCEPTED_INPUTS)
    supplied[name] = rejected

    completed = _run_script(tmp_path, inputs=supplied)

    assert completed.returncode != 0
    assert name.encode("utf-8") in completed.stderr


@pytest.mark.parametrize("rejected", ["yes", "1", "TRUE", ""])
def test_the_release_script_refuses_a_malformed_authorization(
    tmp_path, rejected
):
    """The Cloud Function authorization accepts two values only."""
    supplied = dict(ACCEPTED_INPUTS)
    supplied["CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED"] = rejected

    completed = _run_script(tmp_path, inputs=supplied)

    assert completed.returncode != 0


def test_the_release_script_resolves_its_paths_from_its_own_location():
    """Nothing is resolved against the directory the script was run in."""
    text = _script_text()

    assert 'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"' \
        in text
    assert 'REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"' in text
    assert "./functions" not in text


def test_the_release_script_builds_from_definitions_that_exist():
    """Every image is built from a Dockerfile and context that exist.

    The previous form built the repository root, where there is no
    Dockerfile, so the build could only fail.
    """
    text = _script_text()
    dockerfiles = dict(
        (found.group("key"), found.group("value"))
        for found in ARRAY_ENTRY.finditer(
            text.split("WORKLOAD_DOCKERFILE=(")[1].split(")")[0]
        )
    )
    contexts = dict(
        (found.group("key"), found.group("value"))
        for found in ARRAY_ENTRY.finditer(
            text.split("WORKLOAD_CONTEXT=(")[1].split(")")[0]
        )
    )

    assert sorted(dockerfiles) == sorted(RELEASE_WORKLOADS)
    assert sorted(contexts) == sorted(RELEASE_WORKLOADS)

    for workload in RELEASE_WORKLOADS:
        expected_dockerfile, expected_context = WORKLOAD_BUILD[workload]

        assert dockerfiles[workload] == expected_dockerfile
        assert contexts[workload] == expected_context
        assert (REPO_ROOT / expected_dockerfile).is_file()
        assert (REPO_ROOT / expected_context).is_dir()

    assert "--file " in text


def test_the_release_script_publishes_to_artifact_registry():
    """Images are published to Artifact Registry, not to gcr.io."""
    text = _script_text()

    assert ARTIFACT_REGISTRY_SUFFIX in text
    assert RETIRED_REGISTRY_HOST not in text


def test_the_release_script_reaches_the_cluster_by_region_and_dns():
    """The regional cluster is addressed by region over its DNS endpoint.

    The control plane carries no external IP address, so a public runner
    or workstation reaches it through the DNS-based endpoint, which is
    authorized by IAM rather than by source address.
    """
    credentials = [
        statement
        for statement in _statements("gcloud")
        if "get-credentials" in statement
    ]

    assert len(credentials) == 1

    statement = credentials[0]

    assert "--region=" in statement
    assert "--dns-endpoint" in statement
    assert "--zone" not in statement


def test_the_release_script_mutates_no_ambient_configuration():
    """Neither the active project nor an ambient kubeconfig is written.

    A run writes one context into a kubeconfig of its own, so whichever
    cluster happened to be selected on the host cannot be reached, let
    alone mutated.
    """
    text = _script_text()

    assert "gcloud config set" not in text
    assert 'KUBECONFIG_FILE="$(mktemp)"' in text
    assert 'export KUBECONFIG="${KUBECONFIG_FILE}"' in text
    assert 'context="$(kubectl config current-context)"' in text
    assert 'if [ "${context}" != "${EXPECTED_CONTEXT}" ]; then' in text


def test_the_release_script_asserts_its_inventory_before_it_mutates():
    """The Deployments and containers addressed are checked to exist."""
    text = _script_text()
    # The rollout applies the rendered workload manifests and then waits
    # for each Deployment to converge, so the step that changes the
    # cluster and the step that waits are named separately.
    order = [
        text.index("    assert_release_inventory\n"),
        text.index("    publish_images\n"),
        text.index("    deploy_workloads\n"),
        text.index("    await_rollout\n"),
    ]

    assert order == sorted(order)
    assert "does not exist in namespace" in text
    assert "creates no workload" in text


def test_the_release_script_migrates_before_it_rolls_out():
    """The schema reaches head before either Deployment is changed.

    The previous form set the image and waited for the rollout first, so
    the new code could serve against the old schema, and a failed
    migration was reported only after a partial cutover.
    """
    text = _script_text()
    migrate = text.index("    apply_database_migrations\n")
    roll_out = text.index("    deploy_workloads\n")

    assert migrate < roll_out
    assert "kubectl set image" not in text


def test_the_migration_runs_in_a_pod_of_its_own_with_a_unique_name():
    """The revisions run in a one-shot pod, not in a serving pod.

    The previous form executed them inside whichever pod the label
    selector returned first.
    """
    text = _script_text()
    manifest = _migration_manifest_text()

    # It was a pod the script created and named itself. It is the Job the
    # manifests declare now, rendered by the script and named for the
    # release being deployed, so the name is unique to the attempt without
    # the script composing one -- and the specification is owned by the
    # repository rather than assembled at the keyboard. The name comes from
    # the renderer that renders the manifest, so one derivation serves the
    # object applied and every command issued against it.
    assert '"${RENDER}" migration' in text
    assert '"${RENDER}" job-name migration' in text
    assert "name: ${MIGRATION_JOB_NAME}" in manifest
    assert "restartPolicy: Never" in manifest
    assert "kubectl run" not in text
    assert 'jsonpath="{.items[0].metadata.name}"' not in text


def test_both_paths_take_every_one_shot_job_name_from_the_renderer():
    """Neither path composes a Job name of its own.

    The workflow waited on a twelve-character prefix of the tag while the
    manifest rendered the whole tag, so the wait was issued on an object
    that had never been created, and a forty-character commit put the
    manifest's own name past the length the API server accepts. One
    derivation, in the file that renders the manifest, is what removes both.
    """
    script = _script_text()
    workflow = _workflow_text(CD_WORKFLOW)

    for group in ("migration", "admin-credential"):
        assert '"${RENDER}" job-name %s' % group in script, group
        assert (
            "scripts/render_kubernetes_manifests.sh job-name %s" % group
        ) in workflow, group

    # The two composed forms the paths used, and the truncation that made
    # them disagree.
    assert "IMAGE_TAG:0:" not in workflow
    assert "backend-admin-credential-${IMAGE_TAG" not in workflow
    assert "backend-admin-credential-${VERSION}" not in script
    assert "-migrate-${VERSION}" not in script


def test_the_administrator_job_is_removed_before_it_is_recreated():
    """A reset on a tag that already provisioned is repeatable.

    A completed Job is retained so its record can be read, and a Job's pod
    template cannot be changed in place, so applying the same name again was
    refused -- which is exactly the operation the reset variable exists to
    perform. Both paths delete the previous run and confirm it is gone
    before creating the new one.
    """
    script = _script_text()
    workflow = _step(
        CD_WORKFLOW, "deploy", "Provision the administrator credential"
    )["run"]

    for text in (script, workflow):
        assert "delete" in text
        assert "--wait=true" in text
        assert "still exists after deletion" in text


def test_the_migration_refuses_a_workload_carrying_no_settings():
    """A Deployment with nothing to inherit stops the release.

    The migration reads the same settings the application reads and
    inherits them from the Deployment, so a Deployment declaring neither
    an env nor an envFrom entry means the secret delivery is not wired
    up.
    """
    manifest = _migration_manifest_text()

    # It inherited its settings from a running Deployment, so a Deployment
    # with neither an env nor an envFrom entry had to be refused. The Job
    # declares its own source now and marks it required, so a missing
    # settings map stops the pod before the revisions run -- refused by the
    # cluster rather than by a check in the script. The database credential
    # is not among those sources: it is mounted as a file from the provider
    # class, so no cluster Secret holds it.
    assert "optional: false" in manifest
    assert "configMapRef" in manifest
    assert "secretRef" not in manifest
    assert "secretProviderClass: backend-database" in manifest
    assert "docs/security/RESIDUAL_RISK.md" in _script_text()


def test_the_release_script_refuses_a_reused_tag():
    """A tag that already names published content is refused."""
    text = _script_text()
    refuse = text.index("    refuse_reused_tags\n")
    publish = text.index("    publish_images\n")

    assert refuse < publish
    assert "is already" in text
    assert "has not been used before" in text


def test_the_release_script_rolls_out_by_digest():
    """Every rollout names content, so a moved tag cannot be resolved."""
    text = _script_text()

    assert 'PUBLISHED_IMAGE["${workload}"]="${IMAGE_PREFIX}' \
        '/${workload}@${digest}"' in text
    # The digests reach the cluster through the manifests rather than as
    # arguments to an in-place image mutation, so the rollout applies a
    # specification that already names content.
    assert 'BACKEND_IMAGE="${PUBLISHED_IMAGE[backend]}"' in text
    assert 'FRONTEND_IMAGE="${PUBLISHED_IMAGE[frontend]}"' in text
    assert "kubectl set image" not in text
    assert 'readonly DIGEST_PATTERN=' in text
    assert "verify_running_images" in text
    assert ".imageID" in text


def test_every_kubectl_call_names_the_namespace():
    """No kubectl call falls back to the namespace of a context."""
    for statement in _statements("kubectl"):
        # A context carries no namespace of its own to name, and a
        # namespace is not itself a namespaced resource.
        if statement.startswith(("config ", "get namespace ")):
            continue
        assert "--namespace=" in statement, statement


def test_every_gcloud_call_names_the_project():
    """Project selection is per command rather than global state."""
    for statement in _statements("gcloud"):
        if statement.startswith("auth "):
            continue
        assert "--project=" in statement, statement
        assert "--quiet" in statement, statement


def test_every_wait_in_the_release_script_is_bounded():
    """No step can wait without end."""
    text = _script_text()

    assert 'readonly ROLLOUT_TIMEOUT="10m"' in text
    assert '--timeout="${ROLLOUT_TIMEOUT}"' in text
    # The migration is waited on rather than polled, so its bound is a
    # duration passed to the wait rather than a count of poll seconds.
    assert 'readonly MIGRATION_TIMEOUT="15m"' in text
    assert '--timeout="${MIGRATION_TIMEOUT}"' in text
    assert "readonly COMMAND_TIMEOUT_SECONDS=" in text
    assert text.count('timeout "${COMMAND_TIMEOUT_SECONDS}"') >= 4


def test_the_release_script_preserves_the_pinned_function_runtime():
    """The pinned Cloud Functions runtime is unchanged."""
    assert "--runtime python39" in _script_text()
    assert _constant("CLOUD_FUNCTION_RUNTIME") == PINNED_FUNCTION_RUNTIME


def test_the_cloud_function_step_is_blocked_until_it_is_authorized():
    """The decommissioned runtime is reported, never worked around.

    The pin is frozen, and the runtime it names is decommissioned for
    create and update, so the step is performed only once a release owner
    authorizes it and is otherwise reported as blocked.
    """
    text = _script_text()

    assert 'CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED:-false' in text
    assert 'if [ "${CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED}" != "true" ]' \
        in text
    assert "decommissioned" in text
    assert "was not performed" in text


def test_the_cloud_function_deploy_and_describe_name_one_resource():
    """The status reported is the status of what was just deployed."""
    statements = [
        statement
        for statement in _statements("gcloud")
        if statement.startswith("functions ")
    ]

    # Deploying, reading the status back, removing any public binding and
    # reading the effective policy back are four calls now rather than two.
    # Every one of them has to name the same function in the same project
    # and region, which is the property: a call that named another resource
    # would report on something else.
    assert len(statements) >= 2
    assert _constant("CLOUD_FUNCTION_NAME") == CLOUD_FUNCTION_NAME

    for statement in statements:
        assert '"${CLOUD_FUNCTION_NAME}"' in statement
        assert '--region="${GKE_REGION}"' in statement
        assert '--project="${GCP_PROJECT_ID}"' in statement
        assert "--quiet" in statement


# --- Release workflow ------------------------------------------------------


def test_both_workflows_parse_and_declare_their_jobs():
    """Each workflow is a document with the jobs it is described by."""
    # The single gate job was split into six so that no job's failure can
    # skip another's checks. What matters here is that every job is one of
    # the delivered set, so a job added without a case going with it fails.
    assert sorted(_workflow(CI_WORKFLOW)["jobs"]) == sorted(
        [
            "backend",
            "frontend",
            "infrastructure",
            "integration",
            "postgres-integration",
            "runtime-integration",
        ]
    )
    # A preflight job now runs ahead of the gate, and the image build was
    # separated from the cluster job so the two run on different runners.
    assert sorted(_workflow(CD_WORKFLOW)["jobs"]) == [
        "build",
        "deploy",
        "preflight",
        "verify",
    ]


def test_neither_workflow_reports_an_actionlint_finding():
    """actionlint, which runs ShellCheck over every block, is silent."""
    actionlint = shutil.which("actionlint")
    if actionlint is None:
        pytest.skip("actionlint is unavailable on this host")

    completed = subprocess.run(
        [actionlint, str(CI_WORKFLOW), str(CD_WORKFLOW)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=EXECUTION_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stdout.decode(
        "utf-8", "replace"
    )


def test_every_release_block_opens_with_strict_shell_options():
    """A failing command inside a block ends the step it is in."""
    for job, name, block in _run_blocks(CD_WORKFLOW):
        first = next(
            line.strip() for line in block.splitlines() if line.strip()
        )
        assert first == STRICT_SHELL_OPTIONS, (job, name, first)


def test_the_release_workflow_validates_every_target_value():
    """No target value reaches a command line unchecked.

    Each one is matched whole, so a value carrying whitespace, a leading
    hyphen or a newline is refused rather than parsed as a further
    argument or option.
    """
    block = _step(CD_WORKFLOW, "deploy", "Validate the release target")["run"]

    for name in (
        "PROJECT_ID",
        "GKE_CLUSTER",
        "GKE_REGION",
        "K8S_NAMESPACE",
        "ARTIFACT_REGISTRY_REPOSITORY",
        "RELEASE_SHA",
        "RELEASE_RUN",
    ):
        assert "require " + name in block, name

    assert "if ! [[ $value =~ $pattern ]]; then" in block


def test_the_release_workflow_builds_from_definitions_that_exist():
    """Each image names its Dockerfile, which is not a default path.

    The only image definitions in this repository live under
    infrastructure/docker/, so a build that relied on a default
    Dockerfile in the context directory could only fail.

    Building and publishing were separated onto two steps of a job that
    holds no cluster credential, so no single step both builds and
    publishes any more. The step is found by the command it runs rather
    than by a name, and the property is asserted of every build
    invocation in it: each one names its own definition file, so none can
    fall back on a default path. A loop over a map and two explicit
    invocations satisfy that equally, and the delivered form is the
    second.
    """
    block = _step_running(CD_WORKFLOW, "docker build")["run"]

    invocations = [
        chunk for chunk in block.split("docker build")[1:]
    ]

    assert len(invocations) == len(RELEASE_WORKLOADS)

    for invocation in invocations:
        head = invocation.split("-t ")[0]
        assert " -f " in head or " --file " in head, invocation

    for workload in RELEASE_WORKLOADS:
        dockerfile, context = WORKLOAD_BUILD[workload]

        assert dockerfile in block, workload
        assert "./" + context in block, workload
        assert (REPO_ROOT / dockerfile).is_file()
        assert (REPO_ROOT / context).is_dir()


def test_the_release_workflow_publishes_to_artifact_registry():
    """Images are published to Artifact Registry, not to gcr.io."""
    text = _workflow_text(CD_WORKFLOW)

    assert ARTIFACT_REGISTRY_SUFFIX in text
    assert RETIRED_REGISTRY_HOST not in text


def test_the_release_workflow_reaches_the_cluster_by_region_and_dns():
    """The regional cluster is addressed by region over its DNS endpoint.

    The runner is a public one and the control plane carries no external
    IP address, so the DNS-based endpoint is the path that reaches it,
    and it authorizes by IAM rather than by source address.
    """
    block = _step(CD_WORKFLOW, "deploy", "Get GKE credentials")["run"]

    assert '--region="$GKE_REGION"' in block
    assert "--dns-endpoint" in block
    assert "--zone" not in _workflow_text(CD_WORKFLOW)
    assert 'if [ "$context" != "$EXPECTED_CONTEXT" ]; then' in block
    assert 'kubectl get namespace "$K8S_NAMESPACE"' in block


def test_the_release_workflow_checks_its_inventory_before_it_mutates():
    """Both Deployments and their containers are checked to exist."""
    names = _step_names(CD_WORKFLOW, "deploy")
    block = _step(CD_WORKFLOW, "deploy", "Check the release inventory")["run"]

    assert names.index("Check the release inventory") < names.index(
        "Deploy to GKE"
    )
    assert "for workload in backend frontend; do" in block
    assert "creates no workload" in block


def test_the_release_workflow_migrates_before_it_rolls_out():
    """The schema reaches head before either Deployment is changed."""
    names = _step_names(CD_WORKFLOW, "deploy")

    assert names.index("Apply database migrations") < names.index(
        "Deploy to GKE"
    )


def test_the_migration_pod_carries_a_name_unique_to_the_attempt():
    """A rerun never meets a pod of its own name.

    The previous name was derived from the commit alone, so rerunning one
    commit, or recovering from a cancellation, met a pod that was still
    present or still terminating and stopped before the migration ran.
    """
    block = _step(CD_WORKFLOW, "deploy", "Apply database migrations")["run"]
    text = _workflow_text(CD_WORKFLOW)
    manifest = _migration_manifest_text()

    # The workload is the Job the manifests declare, named for the release
    # being deployed, so a rerun of one commit meets the same name -- and
    # meeting it is safe, because the apply replaces the specification and
    # the cluster reclaims the previous one on its own timer. The name is
    # recorded once, by the step that resolves the release, and every later
    # step reads it from there rather than composing it again: composing it
    # twice is what let a truncated tag be waited on while a whole one was
    # created. It is recorded from the renderer that renders the manifest,
    # so neither side can compose a name the other would not.
    assert (
        "MIGRATION_JOB_NAME=$(scripts/render_kubernetes_manifests.sh "
        "job-name migration)"
    ) in text
    assert "name: ${MIGRATION_JOB_NAME}" in manifest
    assert "MIGRATION_JOB_NAME:?" in block
    assert "RELEASE_RUN: ${{ github.run_id }}-${{ github.run_attempt }}" \
        in text
    assert "restartPolicy: Never" in manifest
    assert "MIGRATION_POD" not in text


def test_the_release_migration_refuses_a_workload_with_no_settings():
    """A Deployment with nothing to inherit stops the release.

    The migration reads the settings the application reads and inherits
    them from the Deployment, so a Deployment declaring neither an env
    nor an envFrom entry means the Secret Manager delivery is not wired
    up.
    """
    manifest = _migration_manifest_text()

    # It inherited its settings from a running Deployment, so a Deployment
    # declaring neither an env nor an envFrom entry had to be refused. The
    # Job declares its own source and marks it required, so a missing
    # settings map stops the pod before the revisions run. The database
    # credential is mounted as a file rather than referenced from a cluster
    # Secret.
    assert "optional: false" in manifest
    assert "configMapRef" in manifest
    assert "secretRef" not in manifest
    assert "secretProviderClass: backend-database" in manifest


def test_the_release_workflow_rolls_out_and_verifies_by_digest():
    """Every rollout names content, and what runs is then checked."""
    deploy = _step(CD_WORKFLOW, "deploy", "Deploy to GKE")["run"]
    checks = _step(
        CD_WORKFLOW, "deploy", "Run post-deployment health checks"
    )["run"]

    # The manifests carry this release's digests, so applying them is the
    # rollout; no separate image mutation is issued against a live object.
    assert "render_kubernetes_manifests.sh workloads" in deploy
    assert "kubectl set image" not in deploy
    resolved = _step(CD_WORKFLOW, "deploy", "Resolve the image references")
    assert "BACKEND_IMAGE" in resolved["run"]
    assert "FRONTEND_IMAGE" in resolved["run"]
    # The digest is read back from the registry in the build job and
    # composed into a reference in the deploy job, so the step that reads
    # it holds a bare sha256 value and the step that consumes it holds the
    # name@digest form. Both halves are required, because a digest read
    # and never composed would leave the rollout naming a tag.
    published = _step(
        CD_WORKFLOW, "build", "Resolve the published digests"
    )["run"]
    assert "image_summary.digest" in published
    assert "sha256:" in published
    assert "@${backend_digest}" in resolved["run"]
    assert "@${frontend_digest}" in resolved["run"]
    assert ".imageID" in checks
    assert 'verify_digest backend "$BACKEND_DIGEST"' in checks
    assert 'verify_digest frontend "$FRONTEND_DIGEST"' in checks


def test_every_release_wait_is_bounded():
    """No step of the release can wait without end."""
    text = _workflow_text(CD_WORKFLOW)
    migrations = _step(
        CD_WORKFLOW, "deploy", "Apply database migrations"
    )["run"]

    assert text.count("--timeout=10m") == 2
    # The migration is waited on rather than polled, so the bound is the
    # duration the wait carries rather than a deadline the shell keeps.
    assert "--for=condition=complete --timeout=15m" in migrations
    assert "activeDeadlineSeconds: 900" in _migration_manifest_text()


def test_the_release_workflow_probes_the_route_it_publishes():
    """The readiness route is probed, not the liveness route alone."""
    checks = _step(
        CD_WORKFLOW, "deploy", "Run post-deployment health checks"
    )["run"]

    assert "/health/ready" in checks
    assert 'kubectl port-forward deployment/backend 8000:8000' in checks
    assert '--namespace="$K8S_NAMESPACE"' in checks


def test_the_release_workflow_is_least_privilege_and_federated():
    """The token is narrow and no long-lived key is accepted."""
    document = _workflow(CD_WORKFLOW)
    text = _workflow_text(CD_WORKFLOW)

    assert document["permissions"] == {"contents": "read"}
    assert document["jobs"]["verify"]["permissions"] == {"contents": "read"}
    assert document["jobs"]["deploy"]["permissions"] == {
        "contents": "read",
        "id-token": "write",
    }
    assert "workload_identity_provider" in text
    assert "service_account_key" not in text
    assert "credentials_json" not in text


def test_the_release_workflow_serializes_and_never_cancels_a_release():
    """A release in flight runs to its end.

    It publishes images, applies revisions and rolls two Deployments
    forward, so a run stopped between those steps would leave the cluster
    part-way through them.
    """
    concurrency = _workflow(CD_WORKFLOW)["concurrency"]

    # The group names the branch that passed the gate. This workflow is
    # triggered by a completed run of another one, and in that trigger
    # ``github.ref`` is the default branch rather than the branch the
    # run was for -- so grouping on it would serialise releases of
    # different branches against each other and leave two releases of
    # one branch free to overlap.
    assert concurrency["group"] == (
        "${{ github.workflow }}"
        "-${{ github.event.workflow_run.head_branch }}"
    )
    assert concurrency["cancel-in-progress"] is False


def test_the_release_workflow_gates_deployment_on_the_security_job():
    """Nothing is deployed until the audit, Bandit and security gates pass."""
    document = _workflow(CD_WORKFLOW)
    verify = document["jobs"]["verify"]

    # The gate is the whole verification workflow rather than a subset of
    # its steps restated here, so the steps are read from the workflow it
    # calls. A gate written out again is a gate that can drift from the
    # checks it is meant to be.
    assert verify["uses"] == "./.github/workflows/ci.yml"
    assert "steps" not in verify

    chain = set()
    pending = ["deploy"]
    while pending:
        declared = document["jobs"].get(pending.pop(), {}).get("needs", [])
        declared = [declared] if isinstance(declared, str) else declared
        for name in declared:
            if name not in chain:
                chain.add(name)
                pending.append(name)
    assert "verify" in chain, chain

    called = [
        step.get("name")
        for job in _workflow(CI_WORKFLOW)["jobs"]
        for step in _steps(CI_WORKFLOW, job)
    ]
    assert "Run pip-audit against the runtime manifest" in called
    assert "Run Bandit" in called
    assert "Run backend security tests" in called


# --- Audit governance ------------------------------------------------------


@pytest.mark.parametrize(
    "manifest,expected",
    [
        ("backend/requirements.txt", RUNTIME_SUPPRESSIONS),
        ("backend/requirements-dev.txt", DEVELOPMENT_SUPPRESSIONS),
    ],
)
def test_each_audit_gate_suppresses_exactly_the_registered_set(
    manifest, expected
):
    """The audit suppresses exactly the registered set, in one place.

    Both workflows ran the audit when this case was written, and the two
    copies had to agree. The delivery workflow calls the verification
    workflow now instead of restating any of its checks, so there is one
    audit rather than two that could disagree -- and the absence of a
    second copy is asserted here so that one cannot reappear.
    """
    assert _suppressed(CI_WORKFLOW, manifest) == expected
    assert not any(
        "pip-audit" in block for _job, _name, block in _run_blocks(
            CD_WORKFLOW
        )
    )


@pytest.mark.parametrize("workflow", [CI_WORKFLOW])
def test_each_audit_gate_names_the_register_that_covers_each_manifest(
    workflow
):
    """The comment beside the suppressions is accurate.

    It previously said every identifier was registered in the
    residual-risk document while that document excluded the development
    set, so the development suppressions were accepted nowhere.
    """
    for _job, _name, block in _run_blocks(workflow):
        if "pip-audit" not in block:
            continue
        assert "docs/security/RESIDUAL_RISK.md" in block
        assert "Runtime register" in block
        assert "Development register" in block
        assert "Eight" in block or "eight" in block
        return
    raise AssertionError("no audit step in " + str(workflow))


@pytest.mark.parametrize(
    "advisory", WITHDRAWN_DEVELOPMENT_SUPPRESSIONS
)
def test_no_withdrawn_development_suppression_returns(advisory):
    """A suppression the instrument's own tree caused is not restored.

    Six identifiers were suppressed against the development manifest only
    because that manifest declared the audit instrument, so the
    instrument's supply chain was reported as this project's. Moving the
    instrument to a manifest no audit reads removes them from the measured
    surface, which is different from ignoring them, and the difference only
    holds while no ignore list names one of them again.
    """
    for workflow in (CI_WORKFLOW, CD_WORKFLOW):
        assert advisory not in _workflow_text(workflow), advisory


def test_the_audit_instrument_is_installed_but_not_audited():
    """The instrument's manifest is installed and read by no audit.

    Auditing it would report the scanner's own dependency tree as the
    project's, which is the accounting the split exists to correct.
    """
    text = _workflow_text(CI_WORKFLOW)

    assert "pip install -r " + AUDIT_MANIFEST in text
    assert "pip-audit --strict -r " + AUDIT_MANIFEST not in text

    for _job, _name, block in _run_blocks(CI_WORKFLOW):
        if "pip-audit --strict" not in block:
            continue
        assert AUDIT_MANIFEST not in block.split("pip-audit --strict")[1]


@pytest.mark.parametrize("workflow", [CI_WORKFLOW, CD_WORKFLOW])
def test_each_workflow_preserves_the_pinned_interpreter(workflow):
    """The interpreter pin is unchanged wherever a workflow sets one."""
    for job, definition in _workflow(workflow)["jobs"].items():
        for step in definition.get("steps", []):
            if "setup-python" not in str(step.get("uses", "")):
                continue
            assert step["with"]["python-version"] == PINNED_INTERPRETER, job


# --- Agreement between the two release paths -------------------------------


def test_both_release_paths_address_one_inventory():
    """The script and the workflow name the same Deployments.

    They previously disagreed: one published a single `app` image and
    updated `app-deployment`, the other published `frontend` and
    `backend` and updated two differently named Deployments, and no
    manifest in this repository defined either set.
    """
    script = _script_text()
    workflow = _workflow_text(CD_WORKFLOW)

    assert 'RELEASE_WORKLOADS=("backend" "frontend")' in script
    assert "for workload in backend frontend; do" in workflow

    for retired in ("app-deployment", "deployment/app "):
        assert retired not in script
        assert retired not in workflow


def test_both_release_paths_publish_to_one_registry_form():
    """One registry host form, and one repository, across both paths."""
    for text in (_script_text(), _workflow_text(CD_WORKFLOW)):
        assert ARTIFACT_REGISTRY_SUFFIX in text
        assert RETIRED_REGISTRY_HOST not in text
        assert "ARTIFACT_REGISTRY_REPOSITORY" in text


def test_both_release_paths_run_the_same_migration_command():
    """One migration vehicle and one command across both paths."""
    script = _script_text()
    workflow = _workflow_text(CD_WORKFLOW)
    manifest = _migration_manifest_text()

    # The command was an override document each path composed for a pod it
    # created, so both had to compose the same one. It is declared once, in
    # the manifest both paths render and apply, so there is one command
    # rather than two that could drift -- and neither path may carry a
    # command of its own.
    assert "python -m alembic -c backend/alembic.ini upgrade head" in manifest
    assert "name: migrate" in manifest
    # Both paths render the same group of the same renderer. The workflow
    # invokes it by path; the script resolves the path once into RENDER
    # and invokes that, so the renderer it reaches is asserted through the
    # assignment rather than expecting the path at the call site.
    assert (
        'readonly RENDER="${REPO_ROOT}/scripts/'
        'render_kubernetes_manifests.sh"'
    ) in script
    assert '"${RENDER}" migration' in script
    assert "render_kubernetes_manifests.sh migration" in workflow
    # What may not appear in either path is an invocation. A comment
    # explaining the vehicle, and a diagnostic naming which command failed
    # when the Job reports failure, are neither of them a second command
    # that could drift from the manifest's -- and both paths carry the
    # same diagnostic sentence, which is how they stay legible together.
    for text in (script, workflow):
        for line in text.split("\n"):
            statement = line.strip()

            if statement.startswith(("#", "echo ")):
                continue

            assert "alembic" not in statement.replace(
                "alembic.ini", ""
            ), statement


# --- Infrastructure the release paths depend on ----------------------------


def test_the_terraform_configuration_is_formatted():
    """``terraform fmt`` reports nothing to change.

    Only formatting is checked here. ``terraform validate`` needs an
    initialised provider directory, which this repository does not carry,
    so it stays a documented command rather than a case.
    """
    terraform = shutil.which("terraform")
    if terraform is None:
        pytest.skip("terraform is unavailable on this host")

    completed = subprocess.run(
        [terraform, "fmt", "-check", "-recursive", "."],
        cwd=str(TERRAFORM_MAIN.parent),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=EXECUTION_TIMEOUT_SECONDS,
    )

    assert completed.returncode == 0, completed.stdout.decode(
        "utf-8", "replace"
    )


def test_the_control_plane_stays_private_and_is_still_reachable():
    """The endpoint is private and a DNS-based endpoint is enabled.

    Private nodes and a private endpoint alone left no path by which a
    public runner or a workstation could reach the API, so a release could
    authenticate and then time out.
    """
    text = _terraform_text()

    assert "enable_private_nodes    = true" in text
    assert "enable_private_endpoint = true" in text
    assert "control_plane_endpoints_config {" in text
    assert "dns_endpoint_config {" in text
    assert "allow_external_traffic = var.gke_dns_endpoint_external_traffic" \
        in text
    assert "container.clusters.connect" in text

    # The wiring alone says nothing about what a deployment gets. This
    # asserts the value the variable actually carries, because the default
    # was true -- so every deployment admitted a caller outside the VPC to
    # the control plane unless it knew to opt out, which is the opposite of
    # the posture the two private-endpoint settings above establish. The
    # default is a bool rather than a quoted string, so the declaration is
    # matched directly.
    block = _variables_text().split(
        'variable "gke_dns_endpoint_external_traffic"'
    )[1].split('\nvariable "')[0]
    assert re.search(r"(?m)^\s+default\s+=\s+false\s*$", block) is not None
    assert re.search(r"(?m)^\s+default\s+=\s+true\s*$", block) is None


def test_the_node_identity_holds_no_project_wide_storage_read():
    """The node identity reads the registry, not every bucket.

    roles/storage.objectViewer was granted by default and admitted by the
    validation. It reads every object in every bucket in the project --
    including the bucket that holds the Cloud Function source archive --
    and it was present only to resolve a gcr.io image name in a project
    still served by Container Registry. The release publishes to Artifact
    Registry, so the role bought nothing this deployment uses.
    """
    variables = _variables_text()
    block = variables.split('variable "gke_node_service_account_roles"')[1]
    block = block.split('\nvariable "')[0]

    # The description names the role in order to say it is refused, so the
    # granted set and the admitted set are read structurally rather than by
    # searching the block for the string.
    granted = block.split("default = [")[1].split("]")[0]
    # An earlier validation also opens with contains([, so the admitted set
    # is anchored on its own terminator and read backwards from there.
    admitted = block.split("], trimspace(role))")[0].split("contains([")[-1]

    for candidate in (granted, admitted):
        assert "roles/storage.objectViewer" not in candidate
        assert "roles/container.defaultNodeServiceAccount" in candidate
        assert "roles/artifactregistry.reader" in candidate

    # And the refusal is stated to whoever supplies the list.
    assert "roles/storage.objectViewer is rejected" in block

    # Nothing else may reintroduce it either, and the repository-scoped
    # pull binding is what keeps image pulls working without it.
    text = _terraform_text()
    assert "roles/storage.objectViewer" not in text
    assert 'resource "google_artifact_registry_repository_iam_member" ' \
        '"gke_nodes"' in text
    assert 'role   = "roles/artifactregistry.reader"' in text


def test_the_cluster_is_regional_and_publishes_its_location():
    """The location is a region, and it is published for the release paths.

    The workflow previously asked for credentials by zone, which a
    regional cluster refuses.
    """
    text = _terraform_text()
    outputs = _outputs_text()

    assert 'resource "google_container_cluster" "primary"' in text
    assert "location = var.region" in text
    assert 'output "kubernetes_cluster_name"' in outputs
    assert 'output "kubernetes_cluster_location"' in outputs
    assert 'output "kubernetes_cluster_dns_endpoint"' in outputs
    assert "not a zone" in outputs


def test_the_release_registry_is_provisioned_with_immutable_tags():
    """The repository both release paths publish to exists.

    Nothing provisioned a registry while both paths pushed to gcr.io,
    which no longer accepts writes. Immutable tags refuse a push that
    would move a tag already in the repository, so a released tag keeps
    naming the content it named.
    """
    text = _terraform_text()

    assert 'resource "google_artifact_registry_repository" "containers"' \
        in text
    assert 'format        = "DOCKER"' in text
    assert "immutable_tags = true" in text
    assert "location      = var.region" in text
    assert "repository_id = var.artifact_registry_repository_id" in text


def test_the_release_registry_carries_writer_and_reader_bindings():
    """Publishing and pulling are both granted, at repository scope."""
    text = _terraform_text()

    assert 'role   = "roles/artifactregistry.writer"' in text
    assert 'role   = "roles/artifactregistry.reader"' in text
    assert "for_each = toset(var.artifact_registry_writer_members)" in text
    assert "google_service_account.gke_nodes.email" in text


def test_the_registry_default_is_the_one_both_release_paths_assume():
    """One repository name across the script, the workflow and Terraform."""
    default = _variable_default("artifact_registry_repository_id")

    assert default == "apartment-finder"
    assert 'ARTIFACT_REGISTRY_REPOSITORY:-' + default in _script_text()


def test_the_published_image_prefix_matches_both_release_paths():
    """The prefix Terraform publishes is the prefix both paths build."""
    outputs = _outputs_text()

    assert '%s-docker.pkg.dev/%s/%s' in outputs
    assert "google_artifact_registry_repository.containers.location" in outputs
    assert "var.project_id" in outputs


def test_every_application_secret_carries_an_accessor_binding():
    """Creating a secret does not deliver it; a binding does.

    Six secrets and their versions existed with no accessor binding and no
    delivery path, so a fresh environment could hold every secret and
    still fail to start. Delivery is now the backend runtime identity's
    own binding over the same six, rather than a plane that granted a
    supplied list of principals access to all of them.
    """
    text = _terraform_text()

    assert 'resource "google_secret_manager_secret_iam_member" ' \
        '"backend_workload"' in text
    assert 'role      = "roles/secretmanager.secretAccessor"' in text
    assert "for_each = local.backend_secret_ids" in text

    for setting in (
        "SECRET_KEY",
        "DATABASE_URL",
        "ZILLOW_API_KEY",
        "PAYPAL_CLIENT_SECRET",
        "PAYPAL_WEBHOOK_ID",
        "SENDGRID_API_KEY",
    ):
        # ``terraform fmt`` aligns the assignments inside the block, so
        # the run of spaces is whatever alignment requires.
        assert re.search(
            r"(?m)^\s+"
            + setting
            + r"\s+=\s+google_secret_manager_secret\.",
            text,
        ), setting


def test_no_binding_grants_a_supplied_list_access_to_every_secret():
    """Each secret is readable by the one identity that reads it.

    A plane existed that took the cross product of every backend secret
    with every principal in a variable, so an identity listed there held
    the signing key and all three provider credentials whatever its
    workload actually read -- and the variable's own description invited
    the migration identity, which needs the connection string alone. The
    grants that remain each name a generated identity, and the migration
    and provisioning identities are bound to their own secrets only -- for
    the provisioner, the connection string and the seed password, with no
    signing key.
    """
    text = _terraform_text()
    variables = _variables_text()

    assert 'resource "google_secret_manager_secret_iam_member" "accessor"' \
        not in text
    assert "secret_accessor_bindings" not in text
    assert "setproduct(" not in text
    assert 'variable "secret_accessor_members"' not in variables

    # The migration identity reads the connection string and nothing else.
    migrate = text.split(
        'resource "google_secret_manager_secret_iam_member" '
        '"backend_migrate"'
    )
    assert len(migrate) == 2
    block = migrate[1].split("\n}")[0]
    assert "google_secret_manager_secret.database_url.secret_id" in block
    for secret in (
        "secret_key",
        "zillow_api_key",
        "paypal_client_secret",
        "paypal_webhook_id",
        "sendgrid_api_key",
    ):
        assert secret not in block, secret

    # The provisioning identity reads the two secrets its job declares and
    # holds neither the token-signing key nor any provider credential. The
    # signing key was withdrawn from the job's mount and from this
    # identity's grants once the command resolved the connection string
    # itself and hashed at the configured cost, so a grant on it here would
    # be a privilege the workload does not read. test_admin_provisioning.py
    # names it among the settings that Job does not mount, and this asserts
    # the grant side of the same withdrawal.
    provisioner = text.split("admin_provisioner_secrets = {")
    assert len(provisioner) == 2
    declared = provisioner[1].split("}")[0]
    for setting in ("DATABASE_URL", "ADMIN_SEED_PASSWORD"):
        assert setting in declared, setting
    for setting in (
        "SECRET_KEY",
        "ZILLOW_API_KEY",
        "PAYPAL_CLIENT_SECRET",
        "PAYPAL_WEBHOOK_ID",
        "SENDGRID_API_KEY",
    ):
        assert setting not in declared, setting


def test_the_accessor_and_writer_principals_are_named_and_not_public():
    """The writer list may not be empty and may not name everyone."""
    variables = _variables_text()

    for name in (
        "artifact_registry_writer_members",
    ):
        block = variables.split('variable "' + name + '"')[1]
        block = block.split('\nvariable "')[0]

        assert "type        = list(string)" in block, name
        assert "default" not in block, name
        assert "allauthenticatedusers" in block, name
        assert "length(var." + name + ") > 0" in block, name


def test_the_cloud_function_and_its_invoker_are_created_together():
    """The whole function footprint is created together or not at all.

    An invoker binding without a function grants nothing, and a function
    without one is reachable by whoever already holds the permission. The
    source archive and its bucket object carry the same gate, so an
    unauthorized deployment provisions no part of the function and the
    outputs the release script reads are null rather than naming an object
    no function consumes.
    """
    text = _terraform_text()
    gate = "count = var.cloud_function_deployment_authorized ? 1 : 0"

    assert text.count(gate) == 4
    assert "google_cloudfunctions_function.function[0].name" in text
    # The attribute alignment inside a block is whatever terraform fmt
    # produces for the longest name in it, so the assignment is matched
    # rather than one particular column.
    assert re.search(
        r'role\s+=\s+"roles/cloudfunctions\.invoker"', text
    ) is not None
    # The additive member form was replaced by the authoritative binding
    # form, which owns every member of the role: applying it removes any
    # public principal an earlier deployment left behind, where the
    # additive form would have added the approved principal beside them
    # and left a public function public. The same variable names the
    # principal, as the sole entry of members, and no _iam_member
    # resource for this role may exist anywhere.
    assert "members = [var.cloud_function_invoker_member]" in text
    assert "google_cloudfunctions_function_iam_binding" in text
    assert "google_cloudfunctions_function_iam_member" not in text


def test_the_cloud_function_is_not_created_until_it_is_authorized():
    """The decommissioned runtime is escalated, not worked around.

    The pin is frozen and the runtime it names is refused for create and
    update, so the resource is left out of the plan until a release owner
    decides the conflict. The same gate exists in the release script.
    """
    text = _terraform_text()
    variables = _variables_text()
    block = variables.split(
        'variable "cloud_function_deployment_authorized"'
    )[1].split('\nvariable "')[0]

    assert "type        = bool" in block
    assert "default     = false" in block
    assert "decommissioned" in block
    assert "docs/security/RESIDUAL_RISK.md" in block
    assert "cloud_function_deployment_authorized" in text
    assert "docs/security/RESIDUAL_RISK.md" in text


def test_terraform_preserves_the_pinned_function_runtime():
    """The pinned Cloud Functions runtime is unchanged."""
    assert 'runtime     = "python39"' in _terraform_text()


def test_the_terraform_function_contract_matches_the_release_script():
    """Terraform and the script govern one function from one archive.

    Terraform managed `function-test` from a bucket archive while the
    script deployed a differently named function from a directory that
    does not exist, so the invoker binding governed neither. A later round
    aligned the names and left two source objects in the same bucket: one
    named for its content digest that the function read, and one at a fixed
    name, built outside Terraform, that the script deployed. The artefact
    released was therefore not provably the artefact Terraform packaged.
    """
    assert _variable_default("cloud_function_name") == CLOUD_FUNCTION_NAME
    assert _variable_default("cloud_function_entry_point") == \
        CLOUD_FUNCTION_ENTRY_POINT

    assert _constant("CLOUD_FUNCTION_NAME") == CLOUD_FUNCTION_NAME
    assert _constant("CLOUD_FUNCTION_ENTRY_POINT") == \
        CLOUD_FUNCTION_ENTRY_POINT

    # One object, named for its content, is what both tools address. The
    # second object and the local-archive input that fed it are gone, so
    # there is no fixed name for an unrelated archive to occupy and no path
    # on the operator's machine that becomes a deployed artefact.
    terraform = _terraform_text()
    variables = _variables_text()
    assert '"google_storage_bucket_object" "cloud_function_source"' \
        not in terraform
    assert 'variable "cloud_function_source_object"' not in variables
    assert 'variable "cloud_function_source_archive"' not in variables
    assert 'variable "cloud_function_source_archive_object"' not in variables

    assert "bucket = google_storage_bucket.static_assets.name" in terraform
    assert "source_archive_bucket = google_storage_bucket_object" \
        ".function_source[0].bucket" in terraform
    assert "source_archive_object = google_storage_bucket_object" \
        ".function_source[0].name" in terraform
    assert 'name   = "function-source-${data.archive_file' \
        '.function_source[0].output_md5}.zip"' in terraform

    # The script no longer restates the object name, and reads the identity
    # of the published archive from the outputs instead.
    script = _script_text()
    for name in RETIRED_FUNCTION_CONSTANTS:
        assert "readonly " + name + "=" not in script, name
    for name in FUNCTION_SOURCE_OUTPUTS:
        assert 'output "' + name + '"' in _outputs_text(), name
        assert name.upper() in script, name

    assert _constant("CLOUD_FUNCTION_SOURCE_BUCKET_SUFFIX") == \
        "-static-assets"
    assert '${var.project_id}-static-assets' in _terraform_text()


def test_the_release_script_verifies_the_archive_digest():
    """The script refuses an object whose bytes are not the published ones.

    Checking that an object exists proves only that something occupies the
    name. The digest Terraform reported is compared with the digest the
    bucket reports, so an archive replaced between the apply and the
    release is refused rather than deployed, and the object name is
    required to carry a content digest so the name cannot be reused for
    different bytes.
    """
    script = _script_text()

    assert 'gcloud storage objects describe "${FUNCTION_SOURCE}"' in script
    assert '--format="value(md5_hash)"' in script
    assert '"${published}" != "${CLOUD_FUNCTION_SOURCE_MD5}"' in script
    assert "FUNCTION_OBJECT_PATTERN='^function-source-[0-9a-f]{32}" in script
    assert "require_input CLOUD_FUNCTION_SOURCE_MD5" in script

    # Both are required only while the function step runs, so a release
    # that leaves the function alone is not blocked for want of an output
    # Terraform reports as null in exactly that state.
    guarded = script.split(
        'if [ "${CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED}" = "true" ]; then'
    )
    assert len(guarded) == 2
    assert "require_input CLOUD_FUNCTION_SOURCE_OBJECT" in guarded[1]


def test_no_output_emits_a_secret_value():
    """Every output is an identifier or an address."""
    outputs = _outputs_text()

    for forbidden in (
        "secret_data",
        "var.secret_key",
        "var.database_url",
        "var.zillow_api_key",
        "var.paypal_client_secret",
        "var.paypal_webhook_id",
        "var.sendgrid_api_key",
    ):
        assert forbidden not in outputs, forbidden

    assert "No output here carries a" in outputs


# --- The register behind the audit gates -----------------------------------


def _register_text():
    """Returns the accepted-residual-risk register as text."""
    return RESIDUAL_RISK_REGISTER.read_text(encoding="utf-8")


def _register_section(manifest):
    """Returns the register section that accounts for one manifest."""
    heading = REGISTER_HEADINGS[manifest]
    text = _register_text()

    assert heading in text, "the register carries no " + heading
    body = text.split(heading, 1)[1]
    return body.split("\n## ", 1)[0]


def _document_text(relative):
    """Returns one advisory-figure document as text."""
    path = REPO_ROOT
    for part in relative.split("/"):
        path = path / part
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("manifest", sorted(REGISTER_HEADINGS))
def test_the_register_carries_one_section_per_audited_manifest(manifest):
    """Each audited manifest has a register section of its own.

    The gates audit two manifests and the register covered one, so the
    development suppressions were accepted in a dependency manifest's
    comment header rather than in an authoritative artifact.
    """
    section = _register_section(manifest)

    assert manifest in section
    assert len(section.splitlines()) > 20, manifest


@pytest.mark.parametrize(
    "manifest,expected",
    [
        ("backend/requirements.txt", RUNTIME_SUPPRESSIONS),
        ("backend/requirements-dev.txt", DEVELOPMENT_SUPPRESSIONS),
    ],
)
def test_every_suppressed_advisory_is_registered_in_its_section(
    manifest, expected
):
    """No identifier is suppressed without an entry that covers it.

    The entry has to sit in the section for the manifest the gate
    suppresses it against, so a runtime identifier documented only under
    the development set would still fail.
    """
    section = _register_section(manifest)

    for advisory in expected:
        assert advisory in section, advisory + " is not registered"


@pytest.mark.parametrize("manifest", sorted(REGISTER_HEADINGS))
def test_no_register_section_claims_an_identifier_it_does_not_cover(
    manifest
):
    """A section lists its own manifest's identifiers and no others.

    The two sets are disjoint, which is what makes the eight suppressions
    eight distinct advisories rather than an overlap.
    """
    own, other = {
        "backend/requirements.txt": (
            RUNTIME_SUPPRESSIONS,
            DEVELOPMENT_SUPPRESSIONS,
        ),
        "backend/requirements-dev.txt": (
            DEVELOPMENT_SUPPRESSIONS,
            RUNTIME_SUPPRESSIONS,
        ),
    }[manifest]

    table = [
        line
        for line in _register_section(manifest).splitlines()
        if line.startswith("| PYSEC-")
    ]
    joined = "\n".join(table)

    assert len(table) == len(own), manifest
    for advisory in other:
        assert advisory not in joined, advisory + " in " + manifest


def test_the_registers_together_account_for_every_suppression():
    """The register total matches what the gate actually suppresses.

    The audit runs in the verification workflow alone, which the
    delivery workflow calls, so that workflow is the one read.
    """
    for workflow in (CI_WORKFLOW,):
        suppressed = set(
            _suppressed(workflow, "backend/requirements.txt")
        ) | set(
            _suppressed(workflow, "backend/requirements-dev.txt")
        )

        assert len(suppressed) == TOTAL_SUPPRESSIONS
        for advisory in suppressed:
            assert advisory in _register_text(), advisory


def test_the_register_states_the_total_suppression_accounting():
    """A reader is told the total, not left to add the sections up."""
    text = _register_text()

    assert "## Development register:" in text
    assert "### The total-suppression accounting" in text
    assert "Eight" in text or "eight" in text
    assert str(TOTAL_SUPPRESSIONS) in text


def test_the_register_no_longer_excludes_the_development_set():
    """The exclusion that hid the second accepted set is gone.

    The register previously said the development advisories were
    "deliberately excluded from every count in this register" while both
    workflows said every suppressed identifier was registered in it.
    """
    text = _register_text()

    assert "deliberately excluded from every count" not in text
    assert "read the development set at its own source" not in text


def test_the_development_manifest_defers_to_the_register():
    """The manifest carries pins, and the register carries the argument.

    Rule 1 puts rationale in the decision log and control evidence in
    the register, so a manifest header is the wrong home for either.
    """
    text = DEVELOPMENT_MANIFEST.read_text(encoding="utf-8")
    header = text.split("\npytest==", 1)[0]
    register = _register_text()

    assert "docs/security/RESIDUAL_RISK.md" in header

    # Every advisory identifier, fix version, measurement and control
    # argument lives in the register alone. The manifest carries pins and a
    # pointer, so one set of facts cannot drift into two.
    assert "Compensating controls" not in text
    assert "ACCEPTED RESIDUAL ADVISORIES" not in text
    assert not re.findall(r"PYSEC-[0-9-]+", text)
    assert set(_suppressed(CI_WORKFLOW, "requirements-dev.txt")) == set(
        DEVELOPMENT_SUPPRESSIONS
    )
    for advisory in DEVELOPMENT_SUPPRESSIONS:
        assert advisory in register, advisory


def test_the_development_manifest_leaves_the_pin_count_to_the_register():
    """It no longer states a pin-site count of its own.

    Its header said the pin was fixed in four places, counting only the
    version declarations. The register's inventory is five, because
    ``@asyncio.coroutine`` pins the interpreter in code as well.
    """
    text = DEVELOPMENT_MANIFEST.read_text(encoding="utf-8")

    assert "four places" not in text
    assert "four places" not in _register_text()
    assert "five places" in _register_text()


@pytest.mark.parametrize("document", sorted(ADVERTISED_FIGURES))
def test_no_document_advertises_the_runtime_seven_as_the_whole(document):
    """Every advertised figure names the population it describes.

    Continuous integration suppressed more identifiers than these
    documents advertised, so the pipeline and the published record
    disagreed about how much risk had been accepted.
    """
    text = _document_text(document)

    for stale in ADVERTISED_FIGURES[document]:
        assert stale not in text, stale

    assert "eight" in text.lower()


def test_the_decision_log_records_the_two_register_decision():
    """The reasoning sits where Rule 1 requires, with its total."""
    text = DECISION_LOG.read_text(encoding="utf-8")

    assert "| 35.1.1 |" in text
    assert "Development register" in text
    assert "**Eight** advisories cannot be fixed" in text
    assert "| Advisories accepted as residual | **8**" in text
