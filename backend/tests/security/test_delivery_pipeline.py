"""Checks over the workflows and the script that build, verify and deploy.

Neither delivery path can be run from this test process, so every property
below is asserted against the declaration itself. Each YAML document is
parsed, and each ``run`` script is additionally handed to a shell for a
syntax check when one is available, so a step that could never execute is
reported here rather than on a pushed branch.

What is asserted:

* both workflows parse, and every job declares an explicit ``permissions``
  block, so neither inherits the broad default token
* every ``run`` script sets the strict shell options, so a failing command
  ends the step instead of being followed by the next one
* the shared rate-limit store's address reaches the workload from managed
  configuration: the deployment reads it from Secret Manager and writes it
  into a Kubernetes secret, and no step carries the address as a literal
* an address naming a store held inside one process is refused by the
  deployment rather than by each pod's own startup validation
* the one manifest inventory both delivery paths apply declares the
  bounds a rollout depends on, and neither path mutates a running object
* every workload in that inventory declares a pod and container security
  context, and the one that runs as uid 0 declares that it does rather
  than omitting the field; the namespace carries the pod-security profile
  each workload is admitted and audited against
* the settings-contract gate the ``infrastructure`` job runs accepts the
  committed inventory, and the containers it exempts from naming the
  published rate-limit store are exactly the ones the manifests declare
  without it
* every secret-delivery class names the workloads that mount it and every
  workload names the class it mounts. The secret boundary is the property a
  reviewer audits from these comments, and a comment naming the wrong
  workload or the wrong class describes a boundary the manifests do not
  implement -- which is the failure this pair of cases was written for
* every invocation of the application -- the container image's command, the
  deployment's command and both continuous-integration invocations --
  starts the ASGI server with forwarded-header handling disabled, so the
  address a rate limit is counted against is the address the connection was
  made from and ``TRUSTED_PROXY_HOPS`` is the only setting that changes it

The application is the authority for what a rate-limit store must be:
:mod:`backend.app.core.config` refuses every in-process scheme under any
environment other than local, and the schemes it accepts are read from it
here rather than restated.

The manifests carry substitution tokens the release renders, and the
renderer is the authority for which files each stage applies and for the
value each optional token carries. Both are read from it rather than
restated, so a manifest added to a stage without a decision is reported by
:func:`test_the_workload_inventory_is_exactly_what_is_declared` and a token
whose default changed cannot silently invalidate a case here.
"""

import importlib.util
import inspect
import io
import os
import re
import shutil
import subprocess
import tempfile

import pytest
import yaml
from conftest import REPO_ROOT

from backend.app.tasks import listing_updater

from backend.app.core.config import (
    IN_PROCESS_RATE_LIMIT_SCHEMES,
    SHARED_RATE_LIMIT_STORAGE_SCHEMES,
)
from backend.app.main import HEALTH_PATH, READINESS_PATH

#: Workflow that verifies a push.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Workflow that deploys a verified commit.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"

#: Both workflows, keyed by the name used in failure messages.
WORKFLOWS = {"ci": CI_WORKFLOW, "cd": CD_WORKFLOW}

#: Facts the deployment requires of the run that triggered it. A
#: ``workflow_run`` run holds this repository's token and the release
#: credentials, which the run that triggered it need not have held, so
#: these four are what establish that the triggering run is this
#: repository's own verified release candidate.
REQUIRED_PROVENANCE = (
    "github.event.workflow_run.conclusion",
    "github.event.workflow_run.event",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_repository.full_name",
)

#: One term of a guard: a context path compared with a quoted literal or
#: with another context path.
GUARD_TERM = re.compile(
    r"^\s*([A-Za-z0-9_.]+)\s*==\s*(?:'([^']*)'|([A-Za-z0-9_.]+))\s*$"
)

#: Repository identity the cases below compare against. Its value is
#: immaterial; what matters is that the base repository and the triggering
#: run's head repository are compared with each other.
REPOSITORY_IDENTITY = "owner/apartment-finder-service"

#: Expression the deployment passes to the gate, and the input it passes
#: it as.
VERIFIED_HEAD = "${{ github.event.workflow_run.head_sha }}"

#: Terraform configuration that provisions the deployed resources.
TERRAFORM_MAIN = REPO_ROOT / "infrastructure" / "terraform" / "main.tf"

#: Container stack that declares the local rate-limit store.
COMPOSE_FILE = (
    REPO_ROOT / "infrastructure" / "docker" / "docker-compose.yml"
)

#: Terraform inputs the configuration above declares.
TERRAFORM_VARIABLES = (
    REPO_ROOT / "infrastructure" / "terraform" / "variables.tf"
)

#: Terraform outputs the configuration above publishes.
TERRAFORM_OUTPUTS = REPO_ROOT / "infrastructure" / "terraform" / "outputs.tf"

#: Setting naming the store the rate-limit counters are kept in. It is
#: also the Secret Manager secret_id and the Kubernetes secret key.
RATE_LIMIT_SETTING = "RATE_LIMIT_STORAGE_URI"

#: Kubernetes secret the deployment publishes that setting into.
RATE_LIMIT_STORE_SECRET = "backend-rate-limit-store"

#: Terraform resource address of the provisioned store.
STORE_RESOURCE = 'resource "google_redis_instance" "rate_limit"'

#: Terraform resource address of the secret carrying its address.
STORE_SECRET_RESOURCE = (
    'resource "google_secret_manager_secret" "rate_limit_storage_uri"'
)

#: Shell options every ``run`` script of more than one command is
#: required to set, so a failing command ends its step.
STRICT_SHELL_OPTIONS = "set -euo pipefail"

#: The steps that do not set the options above, as an exact inventory.
#: Each entry is a ``(workflow, step)`` pair. The case that reads this
#: compares it for equality rather than containment, so a step added
#: without the options fails that case.
STEPS_WITHOUT_STRICT_OPTIONS = frozenset(
    {
        ("ci", "Check the secret and ignore policy"),
        ("ci", "Check the application starts"),
        ("ci", "Run backend security tests"),
        ("ci", "Run backend unit tests"),
        ("ci", "Run the production-dialect integration tests"),
        ("ci", "Verify the application starts"),
    }
)

#: Script that releases the service from an operator's shell.
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy.sh"

#: Script that renders the inventory. It owns which files each stage
#: applies and the value each optional token carries.
RENDER_SCRIPT = REPO_ROOT / "scripts" / "render_kubernetes_manifests.sh"

#: Directory holding the one manifest inventory both delivery paths apply.
MANIFEST_DIR = REPO_ROOT / "infrastructure" / "kubernetes"

#: Gate the ``infrastructure`` job runs the inventory through. It is loaded
#: from its path rather than imported, because ``.github`` is not an
#: importable package name.
MANIFEST_GATE = REPO_ROOT.joinpath(
    ".github", "scripts", "check_manifest_settings_contract.py"
)

#: Every declaration in the inventory, as ``file -> ((kind, name), ...)``.
#: The mapping is compared for equality against what the directory holds,
#: so a manifest added or removed without a decision is reported here. A
#: file may declare more than one object: a workload and the service that
#: fronts it are one unit and are applied together.
EXPECTED_MANIFESTS = {
    "00-namespace.yaml": (("Namespace", "apartment-finder"),),
    "10-service-accounts.yaml": (
        ("ServiceAccount", "backend"),
        ("ServiceAccount", "frontend"),
        ("ServiceAccount", "backend-migrate"),
    ),
    "20-backend-config.yaml": (("ConfigMap", "backend-config"),),
    "30-backend-secrets.yaml": (
        ("SecretProviderClass", "backend-secrets"),
    ),
    "35-migration-secrets.yaml": (
        ("SecretProviderClass", "backend-database"),
    ),
    "40-backend.yaml": (
        ("Deployment", "backend"),
        ("Service", "backend"),
    ),
    "45-backend-hpa.yaml": (("HorizontalPodAutoscaler", "backend"),),
    "50-frontend.yaml": (
        ("Deployment", "frontend"),
        ("Service", "frontend"),
    ),
    "55-frontend-hpa.yaml": (("HorizontalPodAutoscaler", "frontend"),),
    "60-migration-job.yaml": (("Job", "backend-migrate"),),
    "65-ingestion-cronjob.yaml": (("CronJob", "listing-ingestion"),),
    "70-admin-credential-job.yaml": (
        ("ServiceAccount", "admin-provisioner"),
        ("SecretProviderClass", "backend-admin-credential"),
        ("Job", "backend-admin-credential"),
    ),
}

#: Name each one-shot Job is rendered under, as
#: ``token -> (renderer group, recorded stem)``. The renderer derives the
#: whole name from the image tag rather than the manifest assembling it, so
#: the token carries the stem and the release component together and the
#: substitution below stands in for both.
#: :func:`test_each_one_shot_job_is_named_by_the_renderer` asserts each
#: entry against the renderer, so the stand-in cannot drift from it.
DERIVED_JOB_NAMES = {
    "MIGRATION_JOB_NAME": ("migration", "backend-migrate"),
    "ADMIN_CREDENTIAL_JOB_NAME": (
        "admin-credential",
        "backend-admin-credential",
    ),
}

#: The one-shot schema migration, and the stage that applies it.
MIGRATION_MANIFEST = "60-migration-job.yaml"

#: Container inside the migration job.
MIGRATION_CONTAINER = "migrate"

#: The periodic listing-refresh workload, and the stage that runs it.
INGESTION_MANIFEST = "65-ingestion-cronjob.yaml"

#: Container inside the ingestion schedule.
INGESTION_CONTAINER = "ingest"

#: The workloads that run continuously, and the port each serves on.
WORKLOAD_PORTS = {"backend": 8000, "frontend": 80}

#: Manifest each continuously running workload is declared in.
WORKLOAD_MANIFESTS = {
    "backend": "40-backend.yaml",
    "frontend": "50-frontend.yaml",
}

#: Autoscaler each workload carries.
WORKLOAD_AUTOSCALERS = {
    "backend": "45-backend-hpa.yaml",
    "frontend": "55-frontend-hpa.yaml",
}

#: Token each workload's container carries in place of an image. No
#: manifest names a registry, a project or a tag, so the same declarations
#: apply to every environment and both delivery paths substitute the same
#: two references -- each of which is resolved to a digest, so a tag moved
#: between the build and the rollout cannot be picked up in its place.
IMAGE_TOKENS = {
    "backend": "${BACKEND_IMAGE}",
    "frontend": "${FRONTEND_IMAGE}",
}

#: Configuration objects the backend workload reads its settings from, in
#: order. The settings map carries no credential; the secret carries the
#: one setting the deployment publishes, because the shared store requires
#: an AUTH string and the application refuses the in-process default
#: outside a local run. The six Secret Manager credentials appear in
#: neither: they are mounted as files, so they enter no cluster object.
BACKEND_CONFIGURATION_SOURCES = (
    ("configMapRef", "backend-config"),
    ("secretRef", RATE_LIMIT_STORE_SECRET),
)

#: Every workload object in the inventory, as
#: ``manifest -> ((kind, container name), ...)``. Compared for equality
#: against the objects the inventory declares that carry a pod template, so
#: a workload added without a decision is reported rather than skipped by
#: the security-context cases below.
WORKLOAD_CONTAINERS = {
    "40-backend.yaml": (("Deployment", "backend"),),
    "50-frontend.yaml": (("Deployment", "frontend"),),
    "60-migration-job.yaml": (("Job", "migrate"),),
    "65-ingestion-cronjob.yaml": (("CronJob", "ingest"),),
    "70-admin-credential-job.yaml": (("Job", "admin-credential"),),
}

#: Container-level settings every workload declares identically. A
#: capability the container adds back is asserted separately, per workload.
REQUIRED_CONTAINER_SECURITY = {
    "allowPrivilegeEscalation": False,
    "readOnlyRootFilesystem": True,
}

#: The seccomp profile every pod declares.
REQUIRED_SECCOMP = {"type": "RuntimeDefault"}

#: Pod-level identity every workload declares, keyed by manifest. The
#: frontend is the one entry that is not the unprivileged shape, and it is
#: recorded here as what it is rather than omitted from the comparison.
#: ``docs/security/DECISION_LOG.md`` rows 96.6.1 and 96.6.2 own it.
WORKLOAD_POD_IDENTITY = {
    "40-backend.yaml": {
        "runAsNonRoot": True, "runAsUser": 1001, "runAsGroup": 1001,
    },
    "50-frontend.yaml": {"runAsNonRoot": False},
    "60-migration-job.yaml": {
        "runAsNonRoot": True, "runAsUser": 1001, "runAsGroup": 1001,
    },
    "65-ingestion-cronjob.yaml": {
        "runAsNonRoot": True, "runAsUser": 1001, "runAsGroup": 1001,
    },
    "70-admin-credential-job.yaml": {
        "runAsNonRoot": True, "runAsUser": 1001, "runAsGroup": 1001,
    },
}

#: Capabilities each workload's container adds after dropping ALL, keyed by
#: manifest. Only the frontend adds one, because it serves on a privileged
#: port.
WORKLOAD_ADDED_CAPABILITIES = {
    "40-backend.yaml": (),
    "50-frontend.yaml": ("NET_BIND_SERVICE",),
    "60-migration-job.yaml": (),
    "65-ingestion-cronjob.yaml": (),
    "70-admin-credential-job.yaml": (),
}

#: The pod-security profile the namespace declares, as
#: ``label suffix -> level``. enforce admits every workload in the
#: inventory; audit and warn are stricter, so the one workload that is not
#: unprivileged is recorded and reported rather than passing unremarked.
NAMESPACE_POD_SECURITY = {
    "enforce": "baseline",
    "audit": "restricted",
    "warn": "restricted",
}

#: Prefix the three labels above share.
POD_SECURITY_LABEL_PREFIX = "pod-security.kubernetes.io/"

#: Probes every continuously running workload declares.
REQUIRED_PROBES = ("startupProbe", "readinessProbe", "livenessProbe")

#: Resource dimensions every container declares on both sides.
RESOURCE_DIMENSIONS = ("cpu", "memory")

#: Dockerfile each image is built from, keyed by the image it produces.
#: Neither build context holds a Dockerfile, so each build names one.
EXPECTED_DOCKERFILES = {
    "backend": "infrastructure/docker/Dockerfile.backend",
    "frontend": "infrastructure/docker/Dockerfile.frontend",
}

#: Program every invocation of this application runs.
ASGI_SERVER = "uvicorn"

#: Text identifying an invocation of this application's own ASGI app,
#: rather than of the server in prose or of another application.
ASGI_APP_MARKER = "uvicorn backend.app.main:app"

#: Flag that leaves the peer address of the connection in the ASGI scope.
#: Without it the server overwrites it from ``X-Forwarded-For`` for any
#: connection arriving from an address it trusts, which is loopback by
#: default, so a caller varying that header is counted as a new client on
#: every request and no per-caller rate limit engages.
NO_PROXY_HEADERS_FLAG = "--no-proxy-headers"

#: Flag forms that put the forwarded header back in force: the first
#: enables the handling outright, the second re-enables it for the
#: addresses it names.
PROXY_TRUST_FLAGS = ("--proxy-headers", "--forwarded-allow-ips")

#: Files that start the application, and the fewest invocations each
#: carries. The documented local command is asserted by
#: ``test_operator_documentation.py``, which owns the README.
ASGI_INVOCATION_SOURCES = {
    "infrastructure/docker/Dockerfile.backend": 1,
    "infrastructure/kubernetes/40-backend.yaml": 1,
    ".github/workflows/ci.yml": 2,
}

#: Characters that make a Dockerfile exec-form command a JSON array, which
#: are replaced with spaces so the command reads as a command line.
JSON_ARRAY_CHARACTERS = re.compile(r"[\"\[\],]")

#: Flag every ``kubectl`` call that reaches the API server carries, so a
#: call that does not answer ends its step rather than holding the job.
#: One pod selector passed to ``kubectl``, in either spelling.
POD_SELECTOR = re.compile(r'--selector=(?:"([^"]*)"|([^\s\\]+))')

KUBECTL_DEADLINE_FLAG = "--request-timeout"

#: Deadline a watch carries instead, because a watch is answered over the
#: life of the operation rather than by one request.
KUBECTL_WATCH_FLAG = "--timeout"

#: ``kubectl`` invocations that reach no API server, or that are meant to
#: outlive their own command, and so carry neither deadline.
#:
#: ``config`` reads the kubeconfig this run wrote and contacts nothing.
#: ``port-forward`` is started in the background and is ended by the trap
#: that follows it, so a deadline on it would end the forward the probes
#: are made through. The third entry is the tool-presence list, where the
#: program is named as a word rather than invoked.
UNBOUNDED_KUBECTL_EXEMPTIONS = (
    "kubectl config",
    "kubectl port-forward",
    "port-forward deployment/backend",
    "for tool in",
)

#: Flags every ``curl`` invocation carries.
CURL_DEADLINE_FLAGS = ("--connect-timeout", "--max-time")

#: Test path holding the security suite. The two backend test steps
#: partition the suite around it rather than overlapping on it.
SECURITY_SUBTREE = "backend/tests/security"

#: One fragment per gate the pipeline runs. Each is asserted to appear
#: exactly once across both workflows, so a gate run twice and a gate lost
#: are both reported.
#:
#: The frontend linter is invoked directly rather than through a package
#: script: frontend/package.json declares none and is a read-only
#: reference in this change set, which the step itself records.
GATE_SIGNATURES = (
    "pip-audit --strict -r backend/requirements.txt",
    "pip-audit --strict -r backend/requirements-dev.txt",
    "bandit -r backend/app -ll",
    "python -m pytest backend/tests/security",
    "python -m pytest backend/tests \\",
    "eslint src --ext .ts,.tsx",
    "flake8 .",
    "npm test -- --coverage",
    "pip show python-multipart",
    "--include=*.py backend/",
)

#: Runtime pins the project freezes, each mapped to the file that
#: carries it. Every entry is asserted to still be in place.
FROZEN_RUNTIME_PINS = {
    ".github/workflows/ci.yml": "python-version: '3.9'",
    "infrastructure/terraform/main.tf": 'runtime     = "python39"',
    "scripts/deploy.sh": "--runtime python39",
    "infrastructure/docker/Dockerfile.backend": "FROM python:3.9-slim",
}


def _document(path):
    """Returns one parsed workflow document."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _jobs(path):
    """Returns one workflow's jobs, keyed by name."""
    return _document(path)["jobs"]


def _steps(path):
    """Returns every ``(job, step)`` pair one workflow declares."""
    pairs = []
    for job, spec in _jobs(path).items():
        for step in spec.get("steps") or []:
            pairs.append((job, step))
    return pairs


def _scripts(path):
    """Returns every ``(job, name, script)`` a workflow runs."""
    return [
        (job, step.get("name", "?"), step["run"])
        for job, step in _steps(path)
        if step.get("run")
    ]


def _deployment_guard():
    """Returns the one condition every deployment job reaches."""
    jobs = _jobs(CD_WORKFLOW)
    conditional = [job for job, spec in jobs.items() if spec.get("if")]
    assert len(conditional) == 1, conditional
    return jobs[conditional[0]]["if"]


def _guard_terms(guard):
    """Returns ``(path, literal, path)`` for each term of a guard.

    The guard is a conjunction, so it is split on ``&&`` and every part has
    to be an equality. A part that is not fails here rather than being
    read wrongly by the evaluator below, which understands conjunction and
    equality and nothing else.
    """
    terms = []
    for part in guard.split("&&"):
        match = GUARD_TERM.match(part)
        assert match, part
        terms.append(match.groups())
    return terms


def _resolve(context, path):
    """Returns the value ``path`` names in ``context``, or ``None``."""
    current = context
    for name in path.split("."):
        if not isinstance(current, dict) or name not in current:
            return None
        current = current[name]
    return current


def _guard_admits(guard, github):
    """Returns whether ``guard`` admits the run ``github`` describes."""
    context = {"github": github}
    for path, literal, other in _guard_terms(guard):
        left = _resolve(context, path)
        right = literal if other is None else _resolve(context, other)
        if left != right:
            return False
    return True


def _github_context(**workflow_run):
    """Returns a context describing a trusted push of this repository.

    Each keyword replaces one field of the triggering run, so a case names
    only the fact it makes untrustworthy.
    """
    run = {
        "conclusion": "success",
        "event": "push",
        "head_branch": "main",
        "head_sha": "0" * 40,
        "head_repository": {"full_name": REPOSITORY_IDENTITY},
    }
    run.update(workflow_run)
    return {
        "repository": REPOSITORY_IDENTITY,
        "event": {"workflow_run": run},
    }


def _render_text():
    """Returns the renderer as one string."""
    return RENDER_SCRIPT.read_text(encoding="utf-8")


def _render_group(name):
    """Returns the manifests the renderer applies for one stage."""
    found = re.search(
        r"(?s)GROUP_%s=\((?P<body>.*?)\n\)" % name, _render_text()
    )
    assert found is not None, name
    return re.findall(r'"([^"]+\.yaml)"', found.group("body"))


def _render_defaults():
    """Returns the value the renderer substitutes for each optional token."""
    found = re.search(
        r"(?s)TOKEN_DEFAULTS=\((?P<body>.*?)\n\)", _render_text()
    )
    assert found is not None, "the renderer declares no token defaults"
    return dict(
        re.findall(r'"([A-Z_][A-Z0-9_]*)=([^"]*)"', found.group("body"))
    )


def _resolved(name):
    """Returns one manifest's text with every token resolved.

    Tokens the renderer carries a default for take that default, so a case
    reading one reads the value a release would apply. The rest are
    replaced with a stand-in, because their values are supplied per
    deployment and no case below reads one.
    """
    body = (MANIFEST_DIR / name).read_text(encoding="utf-8")
    for token, value in _render_defaults().items():
        body = body.replace("${" + token + "}", value)
    for token, (_group, stem) in DERIVED_JOB_NAMES.items():
        body = body.replace(
            "${" + token + "}", "%s-rendered-at-release" % stem
        )
    return re.sub(r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", "rendered-at-release", body)


def _manifest(name):
    """Returns every object one manifest declares, in declaration order."""
    return [
        document
        for document in yaml.safe_load_all(_resolved(name))
        if document
    ]


def _one(name, kind):
    """Returns the single object of one kind in one manifest."""
    matched = [
        document for document in _manifest(name) if document["kind"] == kind
    ]
    assert len(matched) == 1, (name, kind, len(matched))
    return matched[0]


def _pod_spec(document):
    """Returns the pod specification one object declares."""
    if document["kind"] == "CronJob":
        template = document["spec"]["jobTemplate"]["spec"]["template"]
    else:
        template = document["spec"]["template"]
    return template["spec"]


def _container(document, name):
    """Returns the single named container of one object."""
    containers = _pod_spec(document)["containers"]
    matched = [entry for entry in containers if entry["name"] == name]
    assert len(matched) == 1, (name, [e["name"] for e in containers])
    return matched[0]


def _raw_text(name):
    """Returns one manifest exactly as it is committed."""
    return (MANIFEST_DIR / name).read_text(encoding="utf-8")


def _comments(name):
    """Returns one manifest's comment lines as a single flowed string.

    A comment is hard-wrapped, so a citation can straddle a line break;
    joining the lines lets a name be matched whole.
    """
    return " ".join(
        line.lstrip().lstrip("#").strip()
        for line in _raw_text(name).splitlines()
        if line.lstrip().startswith("#")
    )


def _sentences(flowed):
    """Returns one flowed comment split into sentences.

    The split is a period followed by whitespace, which leaves a filename's
    own dot alone -- ``30-backend-secrets.yaml`` is one token here, and a
    citation that landed in two halves could not be found.
    """
    return [part for part in re.split(r"\.\s+", flowed) if part]


def _declared_provider_classes():
    """Returns ``{class name: manifest}`` for every delivery class."""
    declared = {}
    for path in sorted(MANIFEST_DIR.glob("*.yaml")):
        for document in _manifest(path.name):
            if document["kind"] == "SecretProviderClass":
                declared[document["metadata"]["name"]] = path.name
    return declared


def _mounted_provider_classes():
    """Returns ``{manifest: {class name}}`` for every workload that mounts."""
    mounted = {}
    for name in sorted(WORKLOAD_CONTAINERS):
        for document in _manifest(name):
            if "kind" not in document:
                continue
            try:
                pod = _pod_spec(document)
            except KeyError:
                continue
            for volume in pod.get("volumes") or []:
                if "csi" not in volume:
                    continue
                mounted.setdefault(name, set()).add(
                    volume["csi"]["volumeAttributes"]["secretProviderClass"]
                )
    return mounted


def _manifest_gate():
    """Returns the settings-contract gate, loaded from its path.

    The workflow runs it as a script. Loading it here reads the same
    constants the workflow enforces rather than restating them, so the gate
    and the cases below cannot drift apart.
    """
    specification = importlib.util.spec_from_file_location(
        "blitzy_manifest_settings_gate", MANIFEST_GATE
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _configuration_sources(manifest, kind, container):
    """Returns one container's ``envFrom`` entries, or an empty list."""
    return _container(_one(manifest, kind), container).get("envFrom") or []


def _logical_commands(text, program):
    """Returns each invocation of ``program`` as one logical line.

    A shell command continued with a trailing backslash spans several
    physical lines, so the continuations are joined before the deadline
    flags are looked for. Comment lines are dropped, so a program named
    in prose is not mistaken for an invocation.
    """
    joined = text.replace("\\\r\n", " ").replace("\\\n", " ")
    commands = []
    for line in joined.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if re.search(r"(^|[\s|(])" + re.escape(program) + r"\s", line):
            commands.append(" ".join(stripped.split()))
    return commands


def _workflow_commands(path, program):
    """Returns every invocation of ``program`` one workflow makes."""
    commands = []
    for _, step, script in _scripts(path):
        for command in _logical_commands(script, program):
            commands.append((step, command))
    return commands


def _asgi_invocations(relative_path):
    """Returns every start command ``relative_path`` carries.

    A Dockerfile carries its command as a JSON array, so the array's
    punctuation is replaced with spaces before the line is read as a
    command line. Continuations are joined by :func:`_logical_commands`.
    """
    text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
    if "Dockerfile" in relative_path:
        text = JSON_ARRAY_CHARACTERS.sub(" ", text)
    return [
        command
        for command in _logical_commands(text, ASGI_SERVER)
        if ASGI_APP_MARKER in command
    ]


def _every_asgi_invocation():
    """Returns every start command, paired with the file carrying it."""
    return [
        (path, command)
        for path in sorted(ASGI_INVOCATION_SOURCES)
        for command in _asgi_invocations(path)
    ]


def _is_bounded_kubectl(command):
    """Reports whether one ``kubectl`` invocation carries a deadline."""
    if any(exempt in command for exempt in UNBOUNDED_KUBECTL_EXEMPTIONS):
        return True
    return KUBECTL_DEADLINE_FLAG in command or KUBECTL_WATCH_FLAG in command


def _bash():
    """Returns a shell able to parse a script, or ``None``."""
    for candidate in (
        "bash",
        r"C:\Program Files\Git\bin\bash.exe",
        "/bin/bash",
    ):
        resolved = shutil.which(candidate) or (
            candidate if os.path.exists(candidate) else None
        )
        if resolved:
            return resolved
    return None


@pytest.mark.parametrize("name", sorted(WORKFLOWS))
def test_each_workflow_parses_and_declares_jobs(name):
    """Asserts the document is one mapping carrying at least one job.

    A job either runs steps of its own or calls a reusable workflow. The
    deployment's gate is the second: it calls the whole verification
    workflow rather than restating a subset of its steps, so the two can
    never disagree about what a gate is.
    """
    document = _document(WORKFLOWS[name])

    assert isinstance(document, dict)
    assert document["jobs"]
    for job, spec in document["jobs"].items():
        assert spec.get("steps") or spec.get("uses"), (name, job)
        if spec.get("uses"):
            assert str(spec["uses"]).startswith("./.github/workflows/"), (
                name,
                job,
                spec["uses"],
            )


@pytest.mark.parametrize("name", sorted(WORKFLOWS))
def test_every_token_permission_is_declared_rather_than_inherited(name):
    """Asserts neither workflow runs under the broad default token.

    A workflow-level block applies to every job that declares none of its
    own, and a job needing more than it -- the federated identity token
    the deployment exchanges -- is required to declare that itself rather
    than widening the block for every job.
    """
    document = _document(WORKFLOWS[name])

    assert document.get("permissions"), name
    for job, spec in document["jobs"].items():
        declared = spec.get("permissions")
        if declared is None:
            continue
        assert declared, (name, job)
        assert "contents" in declared, (name, job)


def test_only_the_jobs_that_authenticate_request_an_identity_token():
    """Asserts the federated token is granted where it is exchanged only.

    Two jobs authenticate to Google -- one publishes the images and one
    applies them -- and each exchanges the token for a short-lived
    credential. The grant is asserted against the jobs that actually run
    that exchange rather than against a fixed name, so a job given the
    token without using it, and a job using it without declaring it, are
    both reported. The verification workflow exchanges nothing and is
    granted nothing.
    """
    granted = {
        job
        for job, spec in _jobs(CD_WORKFLOW).items()
        if (spec.get("permissions") or {}).get("id-token")
    }
    exchanging = {
        job
        for job, spec in _jobs(CD_WORKFLOW).items()
        for step in (spec.get("steps") or [])
        if str(step.get("uses", "")).startswith("google-github-actions/auth")
    }

    assert granted == exchanging, (sorted(granted), sorted(exchanging))
    assert granted
    assert not [
        job
        for job, spec in _jobs(CI_WORKFLOW).items()
        if (spec.get("permissions") or {}).get("id-token")
    ]


def test_the_inventory_of_steps_without_strict_options_is_exact():
    """Asserts a failing command ends its step wherever it can.

    The steps that do not set the strict options are held as an exact
    inventory, so a step added without them is reported here.
    """
    observed = set()
    for name, path in WORKFLOWS.items():
        for _, step, script in _scripts(path):
            if STRICT_SHELL_OPTIONS not in script:
                observed.add((name, step))

    assert observed == set(STEPS_WITHOUT_STRICT_OPTIONS)


@pytest.mark.parametrize("name", sorted(WORKFLOWS))
def test_the_store_publishing_step_sets_the_strict_options(name):
    """Asserts the store-publishing step ends on a failing command."""
    for _, step, script in _scripts(WORKFLOWS[name]):
        if "rate-limit" not in step:
            continue
        assert STRICT_SHELL_OPTIONS in script, (name, step)


@pytest.mark.parametrize("name", sorted(WORKFLOWS))
def test_every_script_parses_as_a_shell_script(name):
    """Asserts no step carries a script a shell would refuse to run."""
    shell = _bash()
    if shell is None:
        pytest.skip("no shell available to parse the scripts")
    for job, step, script in _scripts(WORKFLOWS[name]):
        handle = tempfile.NamedTemporaryFile(
            "w",
            suffix=".sh",
            prefix="blitzy_adhoc_step_",
            delete=False,
            newline="\n",
            encoding="utf-8",
        )
        try:
            with handle:
                handle.write(script)
            outcome = subprocess.run(
                [shell, "-n", handle.name],
                capture_output=True,
                text=True,
                timeout=60,
            )
        finally:
            os.unlink(handle.name)
        assert outcome.returncode == 0, (
            name,
            job,
            step,
            outcome.stderr,
        )


def test_terraform_provisions_the_shared_rate_limit_store():
    """Asserts a managed store exists for the counters to be shared in.

    The application refuses an in-process store outside a local run, so
    without this resource a deployed workload has nothing to address and
    cannot start at all. The store carries an AUTH string and encrypts the
    connection it is presented over, so the assembled address is itself a
    credential, and it evicts an unreachable counter rather than filling up
    and refusing new writes.
    """
    configuration = TERRAFORM_MAIN.read_text(encoding="utf-8")

    assert STORE_RESOURCE in configuration
    assert 'connect_mode       = "PRIVATE_SERVICE_ACCESS"' in configuration
    assert "auth_enabled            = true" in configuration
    assert 'transit_encryption_mode = "SERVER_AUTHENTICATION"' in (
        configuration
    )
    assert 'maxmemory-policy = "allkeys-lru"' in configuration


def test_terraform_delivers_the_store_address_as_a_secret():
    """Asserts the address is managed configuration, not a literal.

    The payload comes from an ephemeral input consumed by a write-only
    argument, so it reaches neither the plan file nor the state file, and
    the input's own validation accepts the shared schemes only.
    """
    configuration = TERRAFORM_MAIN.read_text(encoding="utf-8")
    inputs = TERRAFORM_VARIABLES.read_text(encoding="utf-8")

    assert STORE_SECRET_RESOURCE in configuration
    assert 'secret_id = "%s"' % RATE_LIMIT_SETTING in configuration
    assert "secret_data_wo         = var.rate_limit_storage_uri" in (
        configuration
    )
    assert 'variable "rate_limit_storage_uri"' in inputs
    assert "ephemeral   = true" in inputs
    for scheme in sorted(IN_PROCESS_RATE_LIMIT_SCHEMES):
        assert scheme in inputs, scheme


def test_the_published_store_output_carries_no_credential():
    """Asserts the store's AUTH string is published by no output."""
    outputs = TERRAFORM_OUTPUTS.read_text(encoding="utf-8")

    assert "google_redis_instance.rate_limit.host" in outputs
    assert "google_redis_instance.rate_limit.port" in outputs
    assert "auth_string" not in outputs


def test_the_deployment_copies_the_address_from_managed_storage():
    """Asserts the workload's address comes from Secret Manager.

    It is read into a file rather than onto a command line, so it appears
    in no process listing, and the Kubernetes secret is built from that
    file rather than from a literal. Both halves name the namespace: the
    kubeconfig the job writes carries none, so a secret created without it
    would land where no workload would ever read it.
    """
    scripts = dict(
        (step, script) for _, step, script in _scripts(CD_WORKFLOW)
    )
    published = [
        script
        for step, script in scripts.items()
        if RATE_LIMIT_SETTING in step or "rate-limit" in step
    ]

    assert len(published) == 1, sorted(scripts)
    script = published[0]
    assert "gcloud secrets versions access latest" in script
    assert "--from-file=" in script
    assert "--from-literal" not in script
    assert "kubectl create secret generic" in script
    assert script.count('--namespace="$K8S_NAMESPACE"') == 2, script


def test_the_store_is_published_after_the_namespace_it_lands_in():
    """Asserts the secret is created once its namespace exists.

    The namespace is one of the prerequisites, so publishing the secret
    before them would create it wherever the context happened to point.
    """
    steps = [
        step for job, step, _ in _scripts(CD_WORKFLOW) if job == "deploy"
    ]
    prerequisites = steps.index("Apply the workload prerequisites")
    publish = steps.index("Publish the shared rate-limit store address")
    migration = steps.index("Apply database migrations")

    assert prerequisites < publish < migration, steps


def test_no_workflow_carries_a_store_address_of_its_own():
    """Asserts no step names a store address as a literal value."""
    for name, path in WORKFLOWS.items():
        text = path.read_text(encoding="utf-8")
        for scheme in sorted(SHARED_RATE_LIMIT_STORAGE_SCHEMES):
            assert scheme + "://" not in text, (name, scheme)


def test_the_deployment_refuses_an_in_process_store_address():
    """Asserts a misconfigured secret fails the deployment, not the pods.

    Every in-process scheme the application refuses is named in the
    guard, so a secret carrying one of them ends the deployment before a
    workload is asked to start under it. The operator's script carries the
    same guard, so a release run by hand refuses the same value.
    """
    scripts = "\n".join(script for _, _, script in _scripts(CD_WORKFLOW))
    manual = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    for scheme in sorted(IN_PROCESS_RATE_LIMIT_SCHEMES):
        expected = scheme.replace("+", r"\+")
        assert expected in scripts, scheme
        assert expected in manual, scheme


def test_the_documented_secret_names_match_across_the_pipeline():
    """Asserts one name is used by Terraform, both paths and the docs."""
    configuration = TERRAFORM_MAIN.read_text(encoding="utf-8")
    workflow = CD_WORKFLOW.read_text(encoding="utf-8")
    manual = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    documented = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")

    assert RATE_LIMIT_SETTING in configuration
    assert ("RATE_LIMIT_SETTING: %s" % RATE_LIMIT_SETTING) in workflow
    assert ('readonly RATE_LIMIT_SETTING="%s"' % RATE_LIMIT_SETTING) in manual
    assert RATE_LIMIT_SETTING in documented


def test_the_example_environment_names_the_provisioned_store():
    """Asserts the documentation points at what is actually provisioned.

    A developer reading the setting needs to know a store exists and how
    to address it, in the container stack and in a deployment alike. The
    template names the setting and its accepted local value; the address of
    each provisioned store is documented where that store is declared, so
    those are read from the compose stack and from the configuration.
    """
    documented = (REPO_ROOT / ".env.example").read_text(encoding="utf-8")
    compose = COMPOSE_FILE.read_text(encoding="utf-8")
    configuration = TERRAFORM_MAIN.read_text(encoding="utf-8")

    assert RATE_LIMIT_SETTING in documented
    assert "bounded-memory://" in documented
    assert "redis://cache:6379/0" in compose
    assert "google_redis_instance" in configuration
    assert "rate_limit" in configuration


def test_the_helper_reads_a_script_from_every_run_step():
    """Asserts the reader here sees every script the workflows run.

    A step whose script the reader missed would escape each assertion
    above, so the count is compared against the documents themselves.
    """
    for name, path in WORKFLOWS.items():
        declared = sum(
            1
            for _, step in _steps(path)
            if isinstance(step.get("run"), str)
        )
        assert declared == len(_scripts(path)), name
        assert declared > 0, name


def test_the_workflow_documents_carry_no_tab_indentation():
    """Asserts neither document uses a character YAML forbids."""
    for name, path in WORKFLOWS.items():
        with io.open(path, encoding="utf-8", newline="") as handle:
            text = handle.read()
        for number, line in enumerate(text.splitlines(), 1):
            assert "\t" not in line, (name, number)


def test_the_workload_inventory_is_exactly_what_is_declared():
    """Asserts the directory holds the inventory and nothing else.

    Both delivery paths render this directory, so a manifest added to it
    and to a stage would be deployed, and one removed would silently stop
    being deployed.
    """
    present = sorted(path.name for path in MANIFEST_DIR.glob("*.yaml"))

    assert present == sorted(EXPECTED_MANIFESTS)


def test_every_manifest_the_renderer_names_is_one_that_exists():
    """Asserts each stage names files the inventory actually holds.

    The renderer is the authority for what a stage applies, so a manifest
    it names and the directory does not carry would fail a release rather
    than a case.
    """
    named = []
    for stage in (
        "PREREQUISITES",
        "MIGRATION",
        "WORKLOADS",
        "ADMIN_CREDENTIAL",
    ):
        group = _render_group(stage)
        assert group, stage
        named.extend(group)

    assert sorted(named) == sorted(EXPECTED_MANIFESTS), sorted(named)
    assert len(named) == len(set(named)), named


@pytest.mark.parametrize("name", sorted(EXPECTED_MANIFESTS))
def test_each_manifest_declares_the_objects_recorded_for_it(name):
    """Asserts each file parses and declares its recorded objects."""
    declared = [
        (document["kind"], document["metadata"]["name"])
        for document in _manifest(name)
    ]
    recorded = list(EXPECTED_MANIFESTS[name])

    assert len(declared) == len(recorded), (name, declared)
    for (kind, actual), (expected_kind, expected_name) in zip(
        declared, recorded
    ):
        assert kind == expected_kind, (name, kind, expected_kind)
        #: A one-shot object carries the release it belongs to in its name,
        #: so the recorded name is its stem.
        assert actual.startswith(expected_name), (name, actual, expected_name)
    for document in _manifest(name):
        assert document["apiVersion"], name


def test_the_one_shot_job_is_kept_out_of_the_workload_apply():
    """Asserts applying the workloads does not touch the migration.

    A finished job's pod template cannot be updated, so the migration is
    applied by its own stage and waited on before any serving image
    changes. Keeping it in a stage of its own is what makes an apply of
    the workloads leave it alone -- the renderer emits exactly the files
    the stage names, so a stage cannot pick up a file by being in the same
    directory as it.
    """
    assert _render_group("MIGRATION") == [MIGRATION_MANIFEST]
    assert MIGRATION_MANIFEST not in _render_group("WORKLOADS")
    assert MIGRATION_MANIFEST not in _render_group("PREREQUISITES")
    assert MIGRATION_MANIFEST not in _render_group("ADMIN_CREDENTIAL")
    for name in _render_group("WORKLOADS"):
        for document in _manifest(name):
            assert document["kind"] != "Job", (name, document["kind"])


@pytest.mark.parametrize("workload", sorted(WORKLOAD_PORTS))
def test_each_workload_declares_the_bounds_a_rollout_depends_on(workload):
    """Asserts replicas, probes, resources and a grace period are set.

    None of these is derived from a workload the pipeline finds in the
    cluster: every one is declared, so a release produces the same shape
    wherever it is run from.
    """
    document = _one(WORKLOAD_MANIFESTS[workload], "Deployment")
    pod = _pod_spec(document)
    container = _container(document, workload)

    assert int(document["spec"]["replicas"]) >= 2
    assert int(pod["terminationGracePeriodSeconds"]) > 0
    for probe in REQUIRED_PROBES:
        assert container[probe]["httpGet"]["port"] == "http", probe
        assert int(container[probe]["periodSeconds"]) > 0, probe
        assert int(container[probe]["timeoutSeconds"]) > 0, probe
    for side in ("requests", "limits"):
        for dimension in RESOURCE_DIMENSIONS:
            assert container["resources"][side][dimension], (side, dimension)
    assert container["ports"][0]["containerPort"] == WORKLOAD_PORTS[workload]
    assert container["securityContext"]["allowPrivilegeEscalation"] is False
    assert container["securityContext"]["readOnlyRootFilesystem"] is True
    assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]


def test_the_workload_security_inventory_covers_every_pod_template():
    """Asserts the cases below read every workload the inventory declares.

    A security-context case that reads a hand-written list is a case that
    silently stops covering a workload added later, and the two Deployments
    were the only ones covered until now. The list is compared for equality
    against the objects the inventory declares that carry a pod template, so
    an addition fails here rather than going unasserted.
    """
    declared = {}
    for name in sorted(EXPECTED_MANIFESTS):
        for document in _manifest(name):
            if document["kind"] not in ("Deployment", "Job", "CronJob"):
                continue
            containers = _pod_spec(document)["containers"]
            declared.setdefault(name, []).append(
                (document["kind"], containers[0]["name"])
            )
            assert len(containers) == 1, (name, len(containers))

    assert {
        name: tuple(entries) for name, entries in declared.items()
    } == WORKLOAD_CONTAINERS
    assert set(WORKLOAD_POD_IDENTITY) == set(WORKLOAD_CONTAINERS)
    assert set(WORKLOAD_ADDED_CAPABILITIES) == set(WORKLOAD_CONTAINERS)


@pytest.mark.parametrize("name", sorted(WORKLOAD_CONTAINERS))
def test_every_workload_declares_its_pod_identity_rather_than_omitting_it(
    name
):
    """Asserts each pod states the identity it runs under.

    An absent ``runAsNonRoot`` and an absent ``runAsUser`` leave the image's
    own user in force, so a pod that runs as uid 0 reads the same as one
    nobody has considered. The frontend is the one workload here that does
    run as uid 0, and it declares ``runAsNonRoot: false`` so that the choice
    is a declaration rather than an omission; rows 96.6.1 and 96.6.2 of
    ``docs/security/DECISION_LOG.md`` own it.
    """
    kind = WORKLOAD_CONTAINERS[name][0][0]
    pod = _pod_spec(_one(name, kind))
    identity = WORKLOAD_POD_IDENTITY[name]

    assert "runAsNonRoot" in pod["securityContext"], name
    for field, value in identity.items():
        assert pod["securityContext"][field] == value, (name, field)
    assert pod["securityContext"]["seccompProfile"] == REQUIRED_SECCOMP, name


@pytest.mark.parametrize("name", sorted(WORKLOAD_CONTAINERS))
def test_every_workload_container_drops_all_and_adds_only_what_it_needs(
    name
):
    """Asserts the container context, and each capability added back.

    Dropping ``ALL`` and then adding one capability is a deliberate,
    reviewable pair. Asserting the drop alone would let an addition through
    unremarked, which is how the one privileged-port capability in this
    inventory came to be unowned.
    """
    kind, container_name = WORKLOAD_CONTAINERS[name][0]
    container = _container(_one(name, kind), container_name)
    context = container["securityContext"]

    for field, value in REQUIRED_CONTAINER_SECURITY.items():
        assert context[field] is value, (name, field)
    assert context["capabilities"]["drop"] == ["ALL"], name
    assert tuple(
        context["capabilities"].get("add", ())
    ) == WORKLOAD_ADDED_CAPABILITIES[name], name


def test_the_namespace_declares_the_pod_security_profile():
    """Asserts admission is governed rather than left to the cluster.

    Without these labels every workload is admitted under whatever the
    cluster default happens to be, so the one pod that runs as uid 0 is
    neither refused nor recorded. ``enforce`` is the level that admits the
    inventory as it stands; ``audit`` and ``warn`` are stricter, so that pod
    is written to the audit log and reported at apply time.
    """
    namespace = _one("00-namespace.yaml", "Namespace")
    labels = namespace["metadata"]["labels"]

    for suffix, level in NAMESPACE_POD_SECURITY.items():
        key = POD_SECURITY_LABEL_PREFIX + suffix
        assert labels.get(key) == level, key
    assert labels["app.kubernetes.io/part-of"] == "apartment-finder"


def test_the_frontend_is_the_only_workload_admitted_below_restricted():
    """Asserts exactly one workload falls short of the audited level.

    ``restricted`` requires ``runAsNonRoot``, so the count of workloads that
    do not declare it is the count the audit level will report. One is the
    recorded position; two would mean a workload had been added without the
    unprivileged shape and without a decision.
    """
    privileged = sorted(
        name
        for name, identity in WORKLOAD_POD_IDENTITY.items()
        if identity.get("runAsNonRoot") is not True
    )

    assert privileged == ["50-frontend.yaml"], privileged
    assert NAMESPACE_POD_SECURITY["enforce"] == "baseline"
    assert NAMESPACE_POD_SECURITY["audit"] == "restricted"
    assert NAMESPACE_POD_SECURITY["warn"] == "restricted"


def test_the_api_probes_read_the_routes_it_actually_publishes():
    """Asserts readiness reads the readiness route, not the liveness one.

    The liveness route answers as soon as the process serves requests,
    so a pod that cannot read its database would pass a readiness probe
    pointed at it and would then be sent traffic it cannot serve. The
    paths are read from the application rather than restated.
    """
    container = _container(_one("40-backend.yaml", "Deployment"), "backend")

    assert container["readinessProbe"]["httpGet"]["path"] == READINESS_PATH
    assert container["livenessProbe"]["httpGet"]["path"] == HEALTH_PATH
    assert container["startupProbe"]["httpGet"]["path"] == HEALTH_PATH
    assert READINESS_PATH.startswith(HEALTH_PATH)


def test_the_api_reads_its_settings_from_managed_configuration():
    """Asserts every configuration source is named and required.

    An optional reference would let a pod start without the settings the
    application validates, so each one is required and the pod names what
    is missing instead.
    """
    container = _container(_one("40-backend.yaml", "Deployment"), "backend")
    declared = [
        (kind, entry[kind]["name"], entry[kind].get("optional"))
        for entry in container["envFrom"]
        for kind in entry
    ]

    assert [(kind, name) for kind, name, _ in declared] == list(
        BACKEND_CONFIGURATION_SOURCES
    )
    assert all(optional is False for _, _, optional in declared)


def test_no_credential_reaches_the_api_through_a_cluster_object():
    """Asserts the six managed credentials are mounted, not copied.

    Each is fetched from Secret Manager by the provider class at pod
    start and read from a file, so none is held by a Kubernetes object
    and none appears as an inline value. The only secret the workload
    references is the one the deployment publishes, whose value the
    application refuses to default outside a local run.
    """
    document = _one("40-backend.yaml", "Deployment")
    container = _container(document, "backend")
    volumes = _pod_spec(document)["volumes"]

    referenced = [
        entry["secretRef"]["name"]
        for entry in container["envFrom"]
        if "secretRef" in entry
    ]
    assert referenced == [RATE_LIMIT_STORE_SECRET], referenced

    delivered = [volume for volume in volumes if "csi" in volume]
    assert len(delivered) == 1, volumes
    attributes = delivered[0]["csi"]["volumeAttributes"]
    assert attributes["secretProviderClass"] == "backend-secrets"
    assert delivered[0]["csi"]["readOnly"] is True

    provider = _one("30-backend-secrets.yaml", "SecretProviderClass")
    assert "secretObjects" not in provider["spec"], provider["spec"].keys()


def test_the_api_reads_the_rate_limit_store_the_pipeline_publishes():
    """Asserts the workload names the secret the deployment writes.

    The deployment copies the store address from Secret Manager into a
    Kubernetes secret; this is the reference that consumes it, so the two
    names are asserted against each other rather than kept in step by
    hand. The operator's script publishes the same name.
    """
    container = _container(_one("40-backend.yaml", "Deployment"), "backend")
    referenced = [
        entry["secretRef"]["name"]
        for entry in container["envFrom"]
        if "secretRef" in entry
    ]
    workflow = CD_WORKFLOW.read_text(encoding="utf-8")
    manual = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert RATE_LIMIT_STORE_SECRET in referenced
    assert (
        "RATE_LIMIT_STORE_SECRET: %s" % RATE_LIMIT_STORE_SECRET
    ) in workflow
    assert (
        'readonly RATE_LIMIT_STORE_SECRET="%s"' % RATE_LIMIT_STORE_SECRET
    ) in manual


def test_the_manifest_settings_gate_passes_against_the_inventory(monkeypatch):
    """Asserts the gate the pipeline runs accepts the committed inventory.

    The gate is a script the ``infrastructure`` job runs and no case here
    ran it, so it and the manifests could contradict each other with
    nothing reporting it -- which is what happened. It resolves its
    directory against the working directory, so the run is anchored at the
    repository root.
    """
    monkeypatch.chdir(REPO_ROOT)
    _manifest_gate().main()


def test_the_gate_exempts_only_the_settings_free_containers():
    """Asserts the gate's exemption is the one the manifests declare.

    Two one-shot operator containers read the settings map and are given no
    published secret, because neither constructs ``Settings``. The gate
    records that pair by name; comparing its record against the manifests
    for equality reports both an exemption that outlived its manifest and a
    workload that quietly stopped naming the store.
    """
    measured = set()
    for manifest, declared in sorted(WORKLOAD_CONTAINERS.items()):
        for kind, container in declared:
            sources = _configuration_sources(manifest, kind, container)
            reads_settings = any("configMapRef" in entry for entry in sources)
            names_secret = any("secretRef" in entry for entry in sources)
            if reads_settings and not names_secret:
                measured.add((manifest, container))

    recorded = set(_manifest_gate().SETTINGS_FREE_CONTAINERS)
    assert recorded == measured, sorted(recorded ^ measured)


def test_every_settings_reader_is_given_the_published_store():
    """Asserts each workload that constructs ``Settings`` receives it.

    The application refuses an in-process rate-limit store outside a local
    run, so a workload that reads the settings map, constructs ``Settings``
    and is not given the published address could not start at all. The two
    containers the gate exempts are asserted to be given no cluster secret
    rather than skipped, and every source either declares is required.
    """
    exempt = set(_manifest_gate().SETTINGS_FREE_CONTAINERS)

    for manifest, declared in sorted(WORKLOAD_CONTAINERS.items()):
        for kind, container in declared:
            sources = _configuration_sources(manifest, kind, container)
            if not any("configMapRef" in entry for entry in sources):
                continue
            referenced = [
                entry["secretRef"]["name"]
                for entry in sources
                if "secretRef" in entry
            ]
            if (manifest, container) in exempt:
                assert referenced == [], (manifest, container, referenced)
            else:
                assert referenced == [RATE_LIMIT_STORE_SECRET], (
                    manifest,
                    container,
                    referenced,
                )
            for entry in sources:
                for reference in entry.values():
                    assert reference.get("optional") is False, entry


@pytest.mark.parametrize("workload", sorted(WORKLOAD_PORTS))
def test_each_workload_carries_a_scaling_range(workload):
    """Asserts the replica range is declared and starts where it sits.

    A minimum below the declared replica count would scale the workload
    down the moment both objects were applied.
    """
    scaler = _one(WORKLOAD_AUTOSCALERS[workload], "HorizontalPodAutoscaler")
    deployment = _one(WORKLOAD_MANIFESTS[workload], "Deployment")
    target = scaler["spec"]["scaleTargetRef"]

    assert target["kind"] == "Deployment"
    assert target["name"] == workload
    assert int(scaler["spec"]["minReplicas"]) == int(
        deployment["spec"]["replicas"]
    )
    assert int(scaler["spec"]["maxReplicas"]) > int(
        scaler["spec"]["minReplicas"]
    )
    assert scaler["spec"]["metrics"][0]["resource"]["name"] == "cpu"


@pytest.mark.parametrize("workload", sorted(WORKLOAD_PORTS))
def test_each_service_addresses_the_port_its_workload_serves(workload):
    """Asserts the service and the container agree on the port."""
    name = WORKLOAD_MANIFESTS[workload]
    service = _one(name, "Service")
    deployment = _one(name, "Deployment")
    container = _container(deployment, workload)
    port = service["spec"]["ports"][0]

    assert service["spec"]["type"] == "ClusterIP"
    assert port["port"] == WORKLOAD_PORTS[workload]
    assert port["targetPort"] == container["ports"][0]["name"]
    assert service["spec"]["selector"] == (
        deployment["spec"]["selector"]["matchLabels"]
    )


def test_the_migration_job_is_bounded_and_cleans_up_after_itself():
    """Asserts the job carries every bound the review asked for.

    Its resource envelope, wall-clock deadline, attempt limit and
    retention are declared here rather than inherited from the API
    deployment at release time, so a job that never finishes cannot hold
    a release open and a job that finishes does not accumulate.
    """
    document = _one(MIGRATION_MANIFEST, "Job")
    spec = document["spec"]
    pod = _pod_spec(document)
    container = _container(document, MIGRATION_CONTAINER)

    assert int(spec["activeDeadlineSeconds"]) > 0
    assert 0 <= int(spec["backoffLimit"]) <= 3
    assert int(spec["ttlSecondsAfterFinished"]) > 0
    assert pod["restartPolicy"] == "Never"
    for side in ("requests", "limits"):
        for dimension in RESOURCE_DIMENSIONS:
            assert container["resources"][side][dimension], (side, dimension)

    #: The command reads each credential the job needs from its mount and
    #: then replaces the shell with the migration, so a missing credential
    #: is reported by name rather than surfacing as a connection failure.
    started = "\n".join(container["command"])
    assert "python -m alembic" in started
    assert "-c backend/alembic.ini" in started
    assert "upgrade head" in started


def test_the_ingestion_schedule_can_observe_a_failed_pass():
    """Asserts a failed ingestion pass reaches the schedule as a failure.

    The schedule decides retry and failed-job history from the container's
    exit status, so the two halves of that contract are asserted together:
    the manifest declares an attempt limit and a failure history, and the
    command runs the pass in a way that lets its failure set the exit
    status. ``update_listings`` re-raises, and the command neither wraps
    the call in an exception handler nor follows it with anything whose
    success would mask it -- so a provider outage or a response the
    adapter cannot read exits non-zero rather than reporting a pass that
    refreshed nothing.
    """
    document = _one(INGESTION_MANIFEST, "CronJob")
    job = document["spec"]["jobTemplate"]["spec"]
    container = _container(document, INGESTION_CONTAINER)
    started = "\n".join(container["command"])

    assert 1 <= int(job["backoffLimit"]) <= 3
    assert int(document["spec"]["failedJobsHistoryLimit"]) > 0
    assert document["spec"]["concurrencyPolicy"] == "Forbid"
    assert _pod_spec(document)["restartPolicy"] == "Never"

    # The pass is the last thing the command runs, and it replaces the
    # shell, so its status is the container's status.
    assert "asyncio.run(update_listings())" in started
    assert started.rstrip().splitlines()[-1].lstrip().startswith("exec ")
    for suppressor in ("|| true", "; true", "set +e", "except"):
        assert suppressor not in started, suppressor

    # The other half of the contract: the pass raises rather than
    # absorbing a failure, and it is read from the module rather than
    # restated here.
    source = inspect.getsource(listing_updater.update_listings)
    handler = source.split("except Exception")[-1]
    assert "db.rollback()" in handler
    assert "\n        raise\n" in handler


def test_the_migration_runs_under_its_own_narrow_identity():
    """Asserts the migration reads one credential, not six.

    It needs the connection string and nothing else, so it runs as its own
    service account and mounts a provider class carrying only that value.
    A job mounting the serving class would hold every credential the API
    holds for the length of a schema change.
    """
    document = _one(MIGRATION_MANIFEST, "Job")
    pod = _pod_spec(document)
    container = _container(document, MIGRATION_CONTAINER)

    delivered = [volume for volume in pod["volumes"] if "csi" in volume]
    assert len(delivered) == 1, pod["volumes"]
    narrow = delivered[0]["csi"]["volumeAttributes"]["secretProviderClass"]
    assert narrow == "backend-database"
    assert narrow != "backend-secrets"

    mounted = yaml.safe_load(
        _one("35-migration-secrets.yaml", "SecretProviderClass")["spec"][
            "parameters"
        ]["secrets"]
    )
    assert [entry["path"] for entry in mounted] == ["DATABASE_URL"]
    assert "DATABASE_URL" in "\n".join(container["command"])

    serving = _pod_spec(_one("40-backend.yaml", "Deployment"))
    assert pod["serviceAccountName"] != serving["serviceAccountName"]


def test_each_delivery_class_names_the_workloads_that_mount_it():
    """Asserts the secret boundary a comment describes is the applied one.

    A reviewer establishes which identity may read which credential from the
    class that carries them, so that comment is the boundary as documented
    and the volumes are the boundary as applied. When the two disagree, the
    documented one is what gets believed: the six-secret class named the
    migration Job and the administrator-credential Job among its readers and
    said no narrower class was declared, while both pods mount classes of
    their own -- so the comment described an identity holding six
    credentials where the manifests grant it one, and the workload that does
    mount all six went unnamed.

    Two directions are asserted. Every workload that mounts the class is
    named by the manifest declaring it, and any other workload named there
    in a sentence about mounting is named beside the class it does mount --
    which admits both the cross-reference a reader needs and a sequencing
    note, while refusing a bare attribution. The comparison is by manifest
    filename rather than by prose label, because a filename is what a reader
    follows and what this case can resolve; a class declared and mounted in
    one file cites no other for itself.
    """
    declared = _declared_provider_classes()
    mounted = _mounted_provider_classes()
    assert declared, "no delivery class is declared"

    for klass, source in sorted(declared.items()):
        mounting = sorted(
            name for name, classes in mounted.items() if klass in classes
        )
        assert mounting, (klass, source)
        cited = _comments(source)
        for name in mounting:
            assert name == source or name in cited, (klass, source, name)
        for name in sorted(set(mounted) - set(mounting)):
            for sentence in _sentences(cited):
                if name not in sentence or "mount" not in sentence:
                    continue
                assert any(
                    other in sentence for other in mounted[name]
                ), (klass, source, name, sentence)


def test_each_workload_cites_the_file_declaring_the_class_it_mounts():
    """Asserts a workload's own comment names the delivery it applies.

    The migration Job attributed its mount to the six-secret manifest while
    its volume named the one-secret class, so a reader following the
    citation arrived at the wider class and read the pod as holding every
    credential. Every manifest declaring a class is a candidate citation:
    the one a workload cites for its own mount has to be the one it mounts,
    and another may be named only in contrast to it.
    """
    declared = _declared_provider_classes()
    sources = set(declared.values())
    mounted = _mounted_provider_classes()
    assert mounted, "no workload mounts a delivery class"

    for name, classes in sorted(mounted.items()):
        cited = _comments(name)
        expected = {declared[klass] for klass in classes}
        for source in sorted(sources):
            if source == name:
                continue
            if source in expected:
                assert source in cited, (name, source)
                continue
            for occurrence in re.finditer(re.escape(source), cited):
                preceding = cited[max(0, occurrence.start() - 80):
                                  occurrence.start()]
                assert "rather than" in preceding, (name, source, preceding)


@pytest.mark.parametrize("token", sorted(DERIVED_JOB_NAMES))
def test_each_one_shot_job_is_named_by_the_renderer(token):
    """Asserts one derivation names the object and every command on it.

    The manifest carries the name as a token, and the renderer derives that
    token from the image tag -- folding it to the alphabet and the length a
    Kubernetes object name accepts. A name a delivery path assembled itself
    could differ from the one the manifest was rendered with, which is how a
    wait can be issued on an object that was never created.
    """
    group, stem = DERIVED_JOB_NAMES[token]
    renderer = _render_text()

    declared = [
        name
        for manifest, expected in EXPECTED_MANIFESTS.items()
        for kind, name in expected
        if kind == "Job" and name == stem
    ]
    assert declared == [stem], declared

    assert '"%s:%s:%s"' % (group, token, stem) in renderer
    assert "job-name" in renderer
    assert "${%s}" % token in "".join(
        (MANIFEST_DIR / manifest).read_text(encoding="utf-8")
        for manifest in EXPECTED_MANIFESTS
    )


def test_the_migration_job_reads_the_same_configuration_as_the_api():
    """Asserts the revisions are applied to the database the API serves.

    A job reading a different configuration could migrate one database
    while the API serves another, so the settings map both read is
    asserted to be one map. The credential secret the API also reads is
    not among the job's sources: it carries the shared rate-limit address,
    which a migration run never reads, and a one-shot pod is given only
    what it reads.
    """
    job = _container(_one(MIGRATION_MANIFEST, "Job"), MIGRATION_CONTAINER)
    api = _container(_one("40-backend.yaml", "Deployment"), "backend")

    def maps(container):
        return [
            entry["configMapRef"]
            for entry in container["envFrom"]
            if "configMapRef" in entry
        ]

    assert maps(job) == maps(api)
    assert maps(job), job["envFrom"]
    assert [entry for entry in job["envFrom"] if "secretRef" in entry] == []


def test_no_manifest_names_a_registry_project_or_tag_of_its_own():
    """Asserts each container carries a substitution token only.

    A manifest naming a registry would apply to one environment and no
    other, and both delivery paths substitute exactly these two
    references, each of them a digest.
    """
    for workload, token in sorted(IMAGE_TOKENS.items()):
        raw = _raw_text(WORKLOAD_MANIFESTS[workload])
        assert "image: %s" % token in raw, workload

    assert "image: %s" % IMAGE_TOKENS["backend"] in _raw_text(
        MIGRATION_MANIFEST
    )

    for path in sorted(MANIFEST_DIR.glob("*.yaml")):
        text = path.read_text(encoding="utf-8")
        assert "gcr.io" not in text, path.name
        assert "docker.pkg.dev" not in text, path.name
        assert "${{" not in text, path.name


def test_each_image_is_built_from_the_dockerfile_that_defines_it():
    """Asserts every build names a real Dockerfile and a real context.

    Neither build context holds a Dockerfile of its own, so a build that
    named no ``-f`` would fail rather than produce the image it was asked
    for.
    """
    builds = _workflow_commands(CD_WORKFLOW, "docker")
    building = [
        command for _, command in builds if "docker build" in command
    ]

    assert len(building) == len(EXPECTED_DOCKERFILES)
    for workload, dockerfile in sorted(EXPECTED_DOCKERFILES.items()):
        assert (REPO_ROOT / dockerfile).is_file(), dockerfile
        assert (REPO_ROOT / workload).is_dir(), workload
        matched = [
            command
            for command in building
            if dockerfile in command and "./" + workload in command
        ]
        assert len(matched) == 1, (workload, building)
    for command in building:
        assert "-f " in command, command
        assert not re.search(r"docker build -t \S+ \./", command), command


def test_the_deploy_script_builds_the_same_two_images():
    """Asserts the script and the workflow build the same artifacts.

    The script holds the Dockerfile and the context per workload in one
    table and builds through it, rather than naming each pair at the call
    site, so the two cannot drift apart within the script. The pairs are
    what is asserted against the workflow's.
    """
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    for workload, dockerfile in sorted(EXPECTED_DOCKERFILES.items()):
        assert '["%s"]="%s"' % (workload, dockerfile) in script, workload
        assert '["%s"]="%s"' % (workload, workload) in script, workload
    assert "docker build -t" not in script
    assert '--file "${dockerfile}"' in script
    assert '--tag "${reference}"' in script


def test_the_cluster_is_addressed_by_one_regional_location():
    """Asserts the location matches the cluster Terraform declares.

    ``google_container_cluster.primary`` sets ``location = var.region``,
    so the cluster is regional and a zone would address it as if it were
    not. One variable carries the value, in both delivery paths.
    """
    workflow = CD_WORKFLOW.read_text(encoding="utf-8")
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    terraform = TERRAFORM_MAIN.read_text(encoding="utf-8")

    assert "location = var.region" in terraform
    for text, label in ((workflow, "cd"), (script, "deploy.sh")):
        assert "--region" in text, label
        assert "--zone" not in text, label
        assert "GKE_REGION" in text, label
        assert "GKE_ZONE" not in text, label


def test_the_cluster_is_reached_over_its_private_endpoint():
    """Asserts neither path can fall back to a public endpoint.

    The control plane carries a private endpoint only, so the credential
    step names the DNS-based endpoint explicitly and the deploying job
    runs on a runner inside the VPC rather than on a hosted one.

    The DNS-based endpoint supersedes the private-address flag rather than
    accompanying it: the two are mutually exclusive, and the DNS endpoint
    is what makes the private control plane reachable from a runner whose
    address is not the cluster's own. The runner label is a repository
    variable, and the workflow refuses to run when it is unset or names a
    hosted image, so the label is asserted against that refusal rather
    than against a fixed string.
    """
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")
    terraform = TERRAFORM_MAIN.read_text(encoding="utf-8")
    workflow = CD_WORKFLOW.read_text(encoding="utf-8")
    deploy = _jobs(CD_WORKFLOW)["deploy"]

    assert "enable_private_endpoint = true" in terraform
    assert "GKE_DEPLOY_RUNNER_LABEL" in str(deploy["runs-on"])
    assert "ubuntu-latest" not in str(deploy["runs-on"])
    assert "GKE_DEPLOY_RUNNER_LABEL is not set" in workflow
    for hosted in ("ubuntu-latest", "windows-latest", "macos-latest"):
        assert '"%s"' % hosted in workflow, hosted

    # Asserted against the invocations rather than the file text, so the
    # prose describing the flag cannot satisfy the case on its own.
    credentials = [
        command
        for _, command in _workflow_commands(CD_WORKFLOW, "gcloud")
        if "get-credentials" in command
    ]
    scripted = [
        command
        for command in _logical_commands(script, "gcloud")
        if "get-credentials" in command
    ]

    assert len(credentials) == 1, credentials
    assert len(scripted) == 1, scripted
    for command in credentials + scripted:
        assert "--dns-endpoint" in command, command
        assert "--internal-ip" not in command, command
        assert "--region" in command, command


def test_the_deployment_applies_the_inventory_rather_than_mutating_it():
    """Asserts the release applies declarations, not in-place edits.

    ``kubectl set image`` changes one field of whatever the cluster holds
    and leaves every other property as it was found, so a workload whose
    probes or resources were never declared keeps not having them. Both
    paths render the manifests, which already carry this release's
    digests, so applying them is the rollout.
    """
    workflow = CD_WORKFLOW.read_text(encoding="utf-8")
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert "render_kubernetes_manifests.sh workloads" in workflow
    assert '"${RENDER}" workloads' in script
    for text, label in ((workflow, "cd"), (script, "deploy.sh")):
        assert "kubectl apply" in text, label
        assert "kubectl set image" not in text, label
        assert "kubectl run " not in text, label
    for token in sorted(IMAGE_TOKENS.values()):
        name = token[2:-1]
        assert name in workflow, name
        assert name in script, name


def test_the_deployment_confirms_the_image_it_asked_for_is_running():
    """Asserts a rollout serving something else fails the release.

    What is read back is what each container reports it is running rather
    than what the specification asked for, so a tag moved between the
    build and the rollout is visible as a digest that does not match.
    """
    scripts = dict(
        (step, script) for _, step, script in _scripts(CD_WORKFLOW)
    )
    verification = scripts["Run post-deployment health checks"]

    assert (
        "jsonpath='{.items[*].status.containerStatuses[*].imageID}'"
        in verification
    )
    assert "which does not carry" in verification
    assert "exit 1" in verification
    for token in sorted(IMAGE_TOKENS):
        assert "verify_digest %s" % token in verification, token


def _pod_selectors(text):
    """Returns every pod selector one release path passes to ``kubectl``."""
    return [
        quoted or bare for quoted, bare in POD_SELECTOR.findall(text)
    ]


def _release_paths():
    """Returns the text of each path that reads back a running pod."""
    scripts = dict(
        (step, script) for _, step, script in _scripts(CD_WORKFLOW)
    )
    return {
        "cd.yml Run post-deployment health checks": scripts[
            "Run post-deployment health checks"
        ],
        "scripts/deploy.sh": DEPLOY_SCRIPT.read_text(encoding="utf-8"),
    }


@pytest.mark.parametrize("path", sorted(_release_paths()))
def test_no_release_path_restates_a_pod_selector(path):
    """Asserts a selector is derived from the object that owns the pods.

    A selector written out here is a second declaration of a label only
    the manifests define. When the two disagree the selector matches no
    pod, and no pod matched reads back as no image -- so the release is
    reported failed after the workloads have already changed, which is
    what a restated ``app=`` selector did.
    """
    text = _release_paths()[path]
    selectors = _pod_selectors(text)

    assert selectors, path
    for selector in selectors:
        assert "$" in selector, (path, selector)
        assert "=" not in selector.replace("${", "").replace("}", ""), (
            path,
            selector,
        )


@pytest.mark.parametrize("path", sorted(_release_paths()))
def test_every_release_path_derives_the_selector_the_manifests_declare(path):
    """Asserts the derived value is read from the Deployment's own field."""
    text = _release_paths()[path]

    assert ".spec.selector.matchLabels" in text, path
    for workload in sorted(WORKLOAD_MANIFESTS):
        assert 'deployment/${workload}' in text or (
            "deployment/%s" % workload
        ) in text, (path, workload)
    assert "declares no pod selector" in text, path


@pytest.mark.parametrize("workload", sorted(WORKLOAD_MANIFESTS))
def test_the_pods_carry_every_label_their_selector_requires(workload):
    """Asserts the derived selector matches the pods it is derived from.

    A Deployment may select on labels its own template does not set, and
    a cluster refuses that; asserting the containment here means the
    value the release derives is a value that matches something.
    """
    deployment = _one(WORKLOAD_MANIFESTS[workload], "Deployment")
    required = deployment["spec"]["selector"]["matchLabels"]
    carried = deployment["spec"]["template"]["metadata"]["labels"]

    assert required, workload
    for key, value in sorted(required.items()):
        assert carried.get(key) == value, (workload, key)


def test_every_remote_call_the_workflow_makes_is_bounded():
    """Asserts no ``kubectl`` or ``curl`` call can wait indefinitely.

    A finite-looking retry loop around an unbounded call is not bounded:
    one attempt that never returns holds the step for as long as the
    connection stays open. A call that reaches no API server, and the
    background forward the probes are made through, are exempt and are
    recorded as such.
    """
    for step, command in _workflow_commands(CD_WORKFLOW, "kubectl"):
        assert _is_bounded_kubectl(command), (step, command)
    for step, command in _workflow_commands(CD_WORKFLOW, "curl"):
        for flag in CURL_DEADLINE_FLAGS:
            assert flag in command, (step, flag, command)


def test_every_remote_call_the_deploy_script_makes_is_bounded():
    """Asserts the script's remote calls carry the same deadlines."""
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    commands = _logical_commands(script, "kubectl")
    assert commands
    for command in commands:
        assert _is_bounded_kubectl(command), command
    for command in _logical_commands(script, "curl"):
        for flag in CURL_DEADLINE_FLAGS:
            assert flag in command, (flag, command)


def test_the_post_deployment_probe_reads_the_readiness_route():
    """Asserts the release is verified against readiness, not liveness.

    Asserted against the invocations rather than the step's text: the
    step's own failure message names the full URL, so reading the text
    would be satisfied by that message alone.

    Liveness answers from the process alone, so a call to it can never
    establish that the release is serving. One such call is made, after
    readiness has already failed and only to report what did answer, and
    it is ended with ``|| true`` so it decides nothing. Every call that
    the release outcome depends on reads readiness.
    """
    probes = _workflow_commands(CD_WORKFLOW, "curl")
    gating = [
        command
        for _, command in probes
        if "|| true" not in command
    ]
    targets = re.findall(
        r"http://[^\s;]+", " ".join(gating)
    )

    assert gating, probes
    assert targets
    assert set(targets) == {"http://127.0.0.1:8000" + READINESS_PATH}, targets
    assert "http://127.0.0.1:8000" + HEALTH_PATH not in targets

    diagnostic = [
        command for _, command in probes if "|| true" in command
    ]
    assert len(diagnostic) == 1, probes
    assert HEALTH_PATH in diagnostic[0]


def test_the_operator_script_probes_both_routes():
    """Asserts a release run by hand reads liveness and readiness.

    A rollout that answers the first and not the second is serving no
    request, so reporting it as healthy on liveness alone would hide
    exactly the failure the readiness route exists to surface.
    """
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert 'probe_endpoint "http://127.0.0.1:${HEALTH_PORT}%s" "liveness"' % (
        HEALTH_PATH
    ) in script
    assert 'probe_endpoint "http://127.0.0.1:${HEALTH_PORT}%s" "readiness"' % (
        READINESS_PATH
    ) in script


def test_the_deploy_script_targets_the_canonical_workloads():
    """Asserts one workload inventory is used by both delivery paths.

    The script previously addressed a deployment named nowhere else and
    applied migrations by running a command inside a serving pod.
    """
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert "app-deployment" not in script
    assert "kubectl exec" not in script
    assert "infrastructure/kubernetes" in script
    assert 'deployment/${workload}' in script
    for workload in sorted(WORKLOAD_PORTS):
        assert 'RELEASE_WORKLOADS=(' in script
        assert '"%s"' % workload in script, workload


def test_the_deploy_script_deploys_no_source_it_does_not_carry():
    """Asserts the function step is withheld rather than guessing.

    The repository carries no ``functions`` directory, so the source is a
    published archive rather than a working-tree path, and the step is
    additionally blocked until a release owner authorizes it, because the
    pinned runtime is one the platform reports as decommissioned.
    """
    script = DEPLOY_SCRIPT.read_text(encoding="utf-8")

    assert not (REPO_ROOT / "functions").exists()
    assert "./functions" not in script
    assert 'FUNCTION_SOURCE="gs://${GCP_PROJECT_ID}"' in script
    assert 'CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED' in script
    assert "--no-allow-unauthenticated" in script
    assert "--allow-unauthenticated" not in script.replace(
        "--no-allow-unauthenticated", ""
    )


def test_every_gate_runs_exactly_once_across_the_two_workflows():
    """Asserts no gate is repeated, and none was lost while deduplicating.

    Each fragment below is a distinct gate. The count is asserted to be
    exactly one across both documents, so a gate removed is reported as
    firmly as a gate run twice.
    """
    combined = "\n".join(
        script
        for path in WORKFLOWS.values()
        for _, _, script in _scripts(path)
    )

    for fragment in GATE_SIGNATURES:
        assert combined.count(fragment) == 1, (
            fragment,
            combined.count(fragment),
        )


def test_the_backend_suite_is_partitioned_rather_than_repeated():
    """Asserts each backend test is executed once.

    The security subtree previously ran twice: once as part of the whole
    suite and once on its own. The unit-test step now excludes it, so the
    two gates partition the suite instead of overlapping.
    """
    scripts = dict(
        (step, script) for _, step, script in _scripts(CI_WORKFLOW)
    )
    security = scripts["Run backend security tests"]
    rest = scripts["Run backend unit tests"]

    assert SECURITY_SUBTREE in security
    assert "--ignore=" + SECURITY_SUBTREE in rest
    assert SECURITY_SUBTREE not in rest.replace(
        "--ignore=" + SECURITY_SUBTREE, ""
    )
    # Coverage spans both halves: the first records, the second appends
    # and is the one that enforces the floor.
    assert "--cov-append" in rest
    assert "--cov-append" not in security
    assert "--cov-fail-under=0" in security
    assert "--cov-fail-under" not in rest


def test_the_deployment_consumes_the_result_rather_than_repeating_it():
    """Asserts the deployment is triggered by a successful CI run.

    It previously ran on the push and re-installed the dependencies, then
    re-ran the audit, Bandit and the security suite that CI had already
    run for the same commit. It now calls that workflow instead, and every
    job reaches the conclusion check through its ``needs`` chain, so no
    job can start from a run that did not succeed.
    """
    document = _document(CD_WORKFLOW)
    triggers = document[True]
    jobs = document["jobs"]

    assert list(triggers) == ["workflow_run"]
    assert triggers["workflow_run"]["workflows"] == [
        _document(CI_WORKFLOW)["name"]
    ]
    assert triggers["workflow_run"]["types"] == ["completed"]

    conditional = [job for job, spec in jobs.items() if spec.get("if")]
    assert len(conditional) == 1, conditional
    guard = jobs[conditional[0]]["if"]
    assert "success" in guard
    assert "workflow_run.conclusion" in guard

    #: Every other job reaches that one, so the guard governs the run.
    reached = {conditional[0]}
    for _ in range(len(jobs)):
        for job, spec in jobs.items():
            needs = spec.get("needs")
            needs = [needs] if isinstance(needs, str) else (needs or [])
            if any(entry in reached for entry in needs):
                reached.add(job)
    assert reached == set(jobs), sorted(set(jobs) - reached)


def test_the_deployment_admits_only_a_trusted_triggering_run():
    """Asserts the guard names every fact a trusted run must carry.

    ``workflow_run`` fires for any completed run of the named workflow,
    including one from a pull request opened from a fork, and the run it
    starts carries this repository's permissions rather than the triggering
    run's. The conclusion alone is therefore not provenance.
    """
    guard = _deployment_guard()
    named = {path for path, _literal, _other in _guard_terms(guard)}

    for path in REQUIRED_PROVENANCE:
        assert path in named, (path, sorted(named))
    assert _guard_admits(guard, _github_context())


@pytest.mark.parametrize(
    "untrusted",
    [
        pytest.param({"conclusion": "failure"}, id="run-did-not-pass"),
        pytest.param({"event": "pull_request"}, id="not-a-push"),
        pytest.param({"head_branch": "topic"}, id="not-the-release-branch"),
        pytest.param(
            {"head_repository": {"full_name": "attacker/apartment-finder"}},
            id="a-fork",
        ),
        pytest.param(
            {
                "event": "pull_request",
                "head_branch": "main",
                "head_repository": {
                    "full_name": "attacker/apartment-finder"
                },
            },
            id="a-fork-pull-request-from-a-branch-named-main",
        ),
    ],
)
def test_the_deployment_refuses_an_untrusted_triggering_run(untrusted):
    """Asserts each untrustworthy run is refused by the guard.

    The last case is the one the trigger's own branch filter does not
    catch: that filter matches the triggering run's head branch, which on a
    fork is the fork's branch name, so a fork branch named for the release
    branch satisfies it.
    """
    guard = _deployment_guard()
    assert not _guard_admits(guard, _github_context(**untrusted)), untrusted


def test_the_deployment_refuses_a_mismatched_repository_identity():
    """Asserts the head repository is compared with this repository."""
    guard = _deployment_guard()
    context = _github_context()
    context["repository"] = "someone-else/apartment-finder"

    assert not _guard_admits(guard, context)


def test_the_gate_verifies_the_commit_the_deployment_releases():
    """Asserts the called gate reads the commit being released.

    A reusable workflow runs the definition its caller holds and checks out
    the caller's revision unless told otherwise, so calling it without the
    released commit would re-verify a different one.
    """
    called = [
        spec
        for spec in _jobs(CD_WORKFLOW).values()
        if str(spec.get("uses", "")).startswith("./.github/workflows/ci.yml")
    ]
    assert called, sorted(_jobs(CD_WORKFLOW))

    document = _document(CI_WORKFLOW)
    declared = document[True]["workflow_call"]["inputs"]
    reference = document["env"]["CHECKOUT_REF"]

    for spec in called:
        passed = spec.get("with") or {}
        carrying = [
            name for name, value in passed.items() if value == VERIFIED_HEAD
        ]
        assert carrying, passed
        for name in carrying:
            assert name in declared, (name, sorted(declared))
            assert name in reference, (name, reference)

    #: Every checkout in the called workflow resolves that one value, so
    #: no job of the gate reads a different revision from another.
    checkouts = [
        step
        for _job, step in _steps(CI_WORKFLOW)
        if str(step.get("uses", "")).startswith("actions/checkout")
    ]
    assert checkouts
    for step in checkouts:
        assert step["with"]["ref"] == "${{ env.CHECKOUT_REF }}", step


def test_the_gate_installs_one_pinned_bootstrap_everywhere():
    """Asserts the installer is pinned, once, and read from there.

    Every job that reads a manifest installs the bootstrap first. An
    unpinned upgrade resolves whatever release the index serves at the
    moment the gate runs, which is a package outside both audited
    manifests executing ahead of the audit itself.
    """
    document = _document(CI_WORKFLOW)
    pinned = document["env"]["PIP_VERSION"]

    assert re.match(r"^\d+(\.\d+)+$", str(pinned)), pinned

    installs = [
        line.strip()
        for _job, _name, script in _scripts(CI_WORKFLOW)
        for line in script.splitlines()
        if "pip install --upgrade" in line
    ]
    assert installs
    for line in installs:
        assert 'pip=="' not in line, line
        assert '"pip==${PIP_VERSION}"' in line, line


def test_the_deployment_releases_the_commit_that_was_verified():
    """Asserts the images are built from the source CI checked.

    A ``workflow_run`` event carries the default branch's head in
    ``github.sha``, which is not necessarily the commit that was checked,
    so the triggering run's own head is what every checkout and every
    image reference uses.
    """
    document = _document(CD_WORKFLOW)
    head = "${{ github.event.workflow_run.head_sha }}"
    checkouts = [
        step
        for _, step in _steps(CD_WORKFLOW)
        if str(step.get("uses", "")).startswith("actions/checkout")
    ]
    text = CD_WORKFLOW.read_text(encoding="utf-8")

    assert document["env"]["RELEASE_SHA"] == head
    assert document["env"]["VERIFIED_SHA"] == head
    assert document["env"]["IMAGE_TAG"] == head
    assert checkouts
    for step in checkouts:
        assert step["with"]["ref"] == head, step
    assert "${{ github.sha }}" not in text

    #: Published to the Artifact Registry repository Terraform provisions,
    #: and rolled out by digest rather than by the tag it was pushed under.
    assert "gcr.io" not in text
    assert '${REGISTRY_LOCATION}-docker.pkg.dev' in text
    for workload in sorted(IMAGE_TOKENS):
        assert '${registry}/%s@${%s_digest}' % (workload, workload) in text


def test_the_deployment_installs_no_verification_tooling():
    """Asserts the deployment does not rebuild CI's environment.

    The gate is reached by calling the verification workflow, so no job
    here installs its dependencies or re-runs one of its gates.
    """
    scripts = "\n".join(
        script for _, _, script in _scripts(CD_WORKFLOW)
    )

    for absent in (
        "pip install -r backend/requirements",
        "pip-audit",
        "bandit ",
        "python -m pytest",
        "npm ci",
        "npm test",
    ):
        assert absent not in scripts, absent


def test_neither_workflow_carries_a_step_that_does_nothing():
    """Asserts no step is a comment block awaiting a human.

    A step whose script runs no command reports success and verifies
    nothing, which reads downstream as a gate that passed.
    """
    for name, path in WORKFLOWS.items():
        for _, step, script in _scripts(path):
            commands = [
                line
                for line in script.splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            assert commands, (name, step)
        text = path.read_text(encoding="utf-8")
        assert "HUMAN ASSISTANCE NEEDED" not in text, name


@pytest.mark.parametrize("path", sorted(FROZEN_RUNTIME_PINS))
def test_every_frozen_runtime_pin_is_still_in_place(path):
    """Asserts the file still carries the runtime pin recorded for it.

    Each pin is read from the file rather than assumed, so a rewrite of
    the file that dropped or moved its pin fails here.
    """
    text = (REPO_ROOT / path).read_text(encoding="utf-8")

    assert FROZEN_RUNTIME_PINS[path] in text


@pytest.mark.parametrize(
    "path,minimum", sorted(ASGI_INVOCATION_SOURCES.items())
)
def test_each_start_command_source_carries_what_is_recorded_for_it(
    path, minimum
):
    """Asserts the invocations are found before they are asserted on.

    A reader of the command form that stopped matching would leave every
    case below asserting over an empty set and reporting success.
    """
    assert len(_asgi_invocations(path)) >= minimum, path


@pytest.mark.parametrize("path,command", _every_asgi_invocation())
def test_every_start_command_leaves_the_client_address_alone(
    path, command
):
    """Asserts the server does not resolve the client address itself.

    The address a request is counted against is read from the ASGI scope
    by ``backend.app.core.rate_limit.client_address``, which at the
    shipped ``TRUSTED_PROXY_HOPS`` of zero uses the address the
    connection was made from. The server overwrites that value from
    ``X-Forwarded-For`` unless this flag is present, and a caller varying
    the header is then a new client on every request.
    """
    assert NO_PROXY_HEADERS_FLAG in command.split(), (path, command)


@pytest.mark.parametrize("path,command", _every_asgi_invocation())
def test_no_start_command_restores_forwarded_header_trust(path, command):
    """Asserts neither enabling form appears beside the flag."""
    tokens = command.split()

    for flag in PROXY_TRUST_FLAGS:
        assert flag not in tokens, (path, command, flag)
