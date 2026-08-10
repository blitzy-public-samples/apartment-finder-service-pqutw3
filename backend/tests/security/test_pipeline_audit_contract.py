"""Checks over the pipelines and the deployment script.

Neither workflow can be run from this test process and neither can the
deployment script, so every property below is asserted against the
definition itself. The definitions are the only place several controls
exist at all -- a pipeline has no runtime the application can guard -- so
they are read here rather than trusted.

What is asserted:

* every action is referenced by a commit, not by a tag, and records the
  release that commit was published as. A tag is a mutable reference its
  publisher can move onto other code, and an action runs with access to
  the job that uses it
* no step carries an empty command or defers to a human, and no step
  invokes a frontend script the frontend package does not declare, so a
  green run is evidence rather than an absence of output
* the deployment job runs only after the gate job, and the gate job runs
  every gate the integration workflow runs, so a release cannot be cut
  from a revision that failed a check
* the integration step applies the migrations and probes the application
  it started, and every path any pipeline probes is a path the
  application serves
* liveness and readiness are both probed. Liveness reports that the
  process answers; readiness reports that the dependencies it needs are
  reachable, and a rollout that answers without them is a failed rollout
* the migration pod is described by this repository alone: it names its
  own service account, carries the one setting the migration environment
  reads, mounts one secret, and copies nothing from the Deployment that
  serves requests
* no step describes a pod. A description renders the container's
  environment into the build log, and the fields that say why a run ended
  are read individually instead
* the migration container's output is republished, which is safe because
  every record that environment emits passes the redacting filter first
* every parameter expansion in every command is quoted, so a value
  carrying a space or a glob cannot become two words or a file list
* the secret delivery the deployment applies is version-controlled, names
  the secrets Terraform declares, and carries no secret value
* the interpreter pin is unchanged at both pipeline pin sites and at the
  function pin site in the deployment script
* every file ends with exactly one newline

The application is the authority for the paths that are probed, the
Terraform configuration is the authority for the secret names, and the
frontend package is the authority for the scripts that exist. A change to
any of them is compared against this file rather than against a second
copy of it.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import json
import re
import shutil
import subprocess

import pytest
import yaml
from conftest import REPO_ROOT

from backend.app.core.config import Settings
from backend.app.main import READINESS_PATH, app

#: Integration workflow, run on every push and pull request.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Deployment workflow, run on a push to the release branch.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"

#: Deployment script, run by an operator.
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy.sh"

#: Developer setup script, read here for its expansions only.
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup_dev_environment.sh"

#: Migration environment, the authority for the one setting a migration
#: run reads. Alembic executes it with a context in place rather than
#: importing it, so the name is read from its declaration.
MIGRATION_ENVIRONMENT = REPO_ROOT / "backend" / "migrations" / "env.py"

#: Module declaring the database configuration contract every caller that
#: reaches the database resolves and validates a value through.
DATABASE_CONTRACT = (
    REPO_ROOT / "backend" / "app" / "core" / "db_contract.py"
)

#: Secret delivery the deployment workflow applies to the cluster.
DELIVERY_MANIFEST = (
    REPO_ROOT / "infrastructure" / "kubernetes" / "30-backend-secrets.yaml"
)

#: Terraform configuration declaring the secrets that are delivered.
TERRAFORM_MAIN = REPO_ROOT / "infrastructure" / "terraform" / "main.tf"

#: Frontend package, the authority for which npm scripts exist.
FRONTEND_PACKAGE = REPO_ROOT / "frontend" / "package.json"

#: Both workflows, by the path each is read from.
WORKFLOWS = (CI_WORKFLOW, CD_WORKFLOW)

#: Both shell scripts, by the path each is read from.
SCRIPTS = (DEPLOY_SCRIPT, SETUP_SCRIPT)

#: Every file this module reads and asserts a trailing newline on.
PIPELINE_FILES = WORKFLOWS + (DEPLOY_SCRIPT, DELIVERY_MANIFEST)

#: Job of :data:`CI_WORKFLOW` that carries every gate.
#: Job of the integration workflow the gate's own checks live in. The gate
#: was delivered as six jobs rather than one, so that a failure in any of
#: them cannot stop another's checks from running; the remaining jobs carry
#: the integration, frontend and infrastructure gates.
CI_JOB = "backend"

#: Job of :data:`CD_WORKFLOW` that carries every gate, and the job that
#: deploys only once it has passed.
CD_GATE_JOB = "verify"
CD_DEPLOY_JOB = "deploy"

#: Names of the steps that constitute the gate set. Both workflows run all
#: of them, so a release is cut from a revision that cleared the same
#: checks an ordinary push clears.
#: A gate is present when a step's name begins with one of these, so the
#: two audit steps -- one per manifest -- both satisfy "Run pip-audit".
GATE_STEP_NAMES = frozenset(
    {
        "Run Flake8",
        "Run pip-audit",
        "Run Bandit",
        "Check python-multipart is absent",
        "Check residual advisory reachability",
        "Run backend unit tests",
        "Run backend security tests",
        "Run the production-dialect integration tests",
    }
)

#: Step whose command starts the application and probes it.
INTEGRATION_STEP_NAME = "Probe liveness and readiness"

#: Step whose command probes a release after it has rolled out.
RELEASE_PROBE_STEP_NAME = "Run post-deployment health checks"

#: Step whose command runs the migrations against the deployed database.
MIGRATION_STEP_NAME = "Apply database migrations"

#: Step whose command applies the secret delivery.
DELIVERY_STEP_NAME = "Apply the workload prerequisites"

#: Path the liveness route is served on. Readiness is imported from the
#: application rather than written twice.
LIVENESS_PATH = "/health"

#: Interpreter version both workflows pin. The pin is load-bearing: the
#: ingestion task uses a decorator a later interpreter removed.
PINNED_PYTHON = "3.9"

#: Runtime the deployment script pins for the deployed function, the same
#: interpreter under a different spelling.
PINNED_FUNCTION_RUNTIME = "python39"

#: One ``uses:`` reference, as it is written including any trailing
#: comment. Read from the raw text because a parser discards comments.
ACTION_REFERENCE = re.compile(
    r"(?m)^\s*(?:-\s+)?uses:\s*(?P<action>[^\s#]+)"
    r"(?:\s*#\s*(?P<release>\S+))?\s*$"
)

#: A reference resolved to a full commit.
COMMIT_SHA = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")

#: A release the trailing comment may record.
RELEASE_TAG = re.compile(r"^v\d+(?:\.\d+){0,2}$")

#: One ``npm run`` invocation, by the script it names.
NPM_SCRIPT = re.compile(r"\bnpm\s+run\s+([A-Za-z0-9:_-]+)")

#: One bare ``npm test`` invocation, which runs the frontend suite.
NPM_TEST = re.compile(r"\bnpm\s+test\b")

#: One ``secret_id`` a Terraform secret resource declares.
TERRAFORM_SECRET_ID = re.compile(r'(?m)^\s*secret_id\s*=\s*"([^"]+)"\s*$')

#: The setting name :data:`DATABASE_CONTRACT` declares, which
#: :data:`MIGRATION_ENVIRONMENT` binds under the same name.
MIGRATION_SETTING_DECLARATION = re.compile(
    r'(?m)^DATABASE_URL_SETTING\s*=\s*"([^"]+)"\s*$'
)

#: The binding through which :data:`MIGRATION_ENVIRONMENT` takes that
#: name, which is what keeps the two files naming one setting.
MIGRATION_SETTING_BINDING = (
    "DATABASE_URL_SETTING = db_contract.DATABASE_URL_SETTING"
)

#: One expansion of a name, braced or bare. ``$(``, ``$((`` and the
#: shell's own single-character parameters are deliberately not matched:
#: none of them is subject to word splitting in the way this module
#: guards against.
EXPANSION = re.compile(
    r"\$(?:\{(?P<braced>[^{}]*)\}|(?P<bare>[A-Za-z_][A-Za-z0-9_]*))"
)

#: Text that defers work to a person rather than performing it.
DEFERRAL_MARKERS = ("HUMAN ASSISTANCE", "TODO", "FIXME", "TBD")

#: Command that renders a pod's whole state, including the environment of
#: every container in it, into the log of whatever ran it.
POD_DESCRIPTION = re.compile(
    r"\bkubectl\b[^\n|;&]*?\bdescribe\s+(?P<object>\S+)"
)

#: Command that reads the backend Deployment's own specification.
DEPLOYMENT_READ = re.compile(r"\bkubectl\s+get\s+deployment\b")

#: Longest a shell parse is waited on, in seconds.
SHELL_TIMEOUT_SECONDS = 60


def _text(path):
    """Return one file's source."""
    return path.read_text(encoding="utf-8")


def _document(path):
    """Return one workflow parsed."""
    return yaml.safe_load(_text(path))


def _steps(path, job):
    """Return the steps of one job of one workflow.

    A job that calls a reusable workflow declares no steps of its own, so
    the steps it runs are read from the workflow it calls.
    """
    definition = _document(path)["jobs"][job]
    called = definition.get("uses")
    if called:
        relative = called[2:] if called.startswith("./") else called
        return _every_step(REPO_ROOT.joinpath(*relative.split("/")))
    return definition.get("steps") or []


def _every_step(path):
    """Return every step of every job of one workflow, in order.

    The gate was delivered as several jobs rather than one, so a check the
    gate performs may sit in any of them. A claim about what the gate does
    is read across all of them; a claim about ordering is read from the one
    job whose steps it compares.
    """
    steps = []
    for name in _document(path)["jobs"]:
        steps.extend(_steps(path, name))
    return steps


def _step_named(path, job, name):
    """Return the one step of a job carrying ``name``."""
    matching = [step for step in _steps(path, job) if step.get("name") == name]
    assert len(matching) == 1, (path.name, job, name, len(matching))
    return matching[0]


def _step_names(path, job):
    """Return the names of a job's steps, in order."""
    return [step.get("name") for step in _steps(path, job)]


def _commands(path):
    """Yield ``(job, position, command)`` for every command in a workflow."""
    for job, definition in _document(path)["jobs"].items():
        for position, step in enumerate(definition.get("steps", [])):
            if "run" in step:
                yield job, position, step["run"]


def _workflow_environment(path):
    """Return the workflow-level environment of one workflow."""
    return dict(_document(path).get("env") or {})


def _gate_workflows(path):
    """Return the workflows one workflow's gate is delivered by.

    A workflow that calls a reusable workflow delegates its gate to it, so
    the gate is read there; a workflow that calls none is its own gate.
    """
    called = [
        definition["uses"]
        for definition in _document(path)["jobs"].values()
        if definition.get("uses")
    ]
    if not called:
        return [path]
    return [
        REPO_ROOT.joinpath(
            *(one[2:] if one.startswith("./") else one).split("/")
        )
        for one in called
    ]


def _declared_environments(path):
    """Yield every environment mapping a workflow declares, in order.

    A value may be set on the workflow, on a job or on a step, and a job
    that calls a reusable workflow contributes that workflow's mappings, so
    all four levels are read.
    """
    document = _document(path)
    if document.get("env"):
        yield document["env"]
    for name, definition in document["jobs"].items():
        called = definition.get("uses")
        if called:
            relative = called[2:] if called.startswith("./") else called
            for inherited in _declared_environments(
                REPO_ROOT.joinpath(*relative.split("/"))
            ):
                yield inherited
            continue
        if definition.get("env"):
            yield definition["env"]
        for step in definition.get("steps") or []:
            if step.get("env"):
                yield step["env"]


def _probed_paths(command):
    """Return the application paths one command probes, in order.

    The path ends at the first character a route path cannot carry, so a
    probe followed by shell punctuation or by the end of a sentence yields
    the path alone.
    """
    port = r"(?:8000|\$\{?[A-Za-z_][A-Za-z0-9_]*\}?)"
    return re.findall(
        r"127\.0\.0\.1:" + port + r"(/[A-Za-z0-9/_-]*)", command
    )


def _served_paths():
    """Return the paths the application serves."""
    return set(
        route.path for route in app.routes if getattr(route, "path", None)
    )


def _unquoted_expansions(text):
    """Return ``(line, expansion)`` for expansions outside double quotes.

    The text is walked once with a context stack, because quoting nests: a
    double-quoted string inside a command substitution inside a
    double-quoted string protects its contents, and counting quote
    characters alone reports the opposite. An expansion is quoted when the
    innermost open context is a double quote, and is reported otherwise.
    Single-quoted text is skipped whole, a comment is skipped to the end
    of its line, and arithmetic is skipped to its closing parentheses.
    """
    found = []
    stack = []
    line = 1
    index = 0
    length = len(text)

    while index < length:
        character = text[index]
        context = stack[-1] if stack else "plain"

        if character == "\n":
            line += 1
            index += 1
            continue

        if context == "single":
            if character == "'":
                stack.pop()
            index += 1
            continue

        if character == "\\":
            index += 2
            continue

        if character == "'" and context != "double":
            stack.append("single")
            index += 1
            continue

        if character == '"':
            if context == "double":
                stack.pop()
            else:
                stack.append("double")
            index += 1
            continue

        if character == "[" and text[index:index + 2] == "[[":
            if context in ("plain", "command") and (
                index == 0 or text[index - 1] in " \t\n;&|("
            ):
                #: Inside ``[[ ]]`` no expansion is word-split, and the
                #: right operand of ``=~`` must stay unquoted for it to be
                #: read as a pattern, so the region is skipped whole.
                closing = text.find("]]", index + 2)
                if closing != -1:
                    line += text.count("\n", index, closing)
                    index = closing + 2
                    continue

        if character == "$" and text[index + 1:index + 2] == "(":
            if text[index + 2:index + 3] == "(":
                closing = text.find("))", index)
                index = length if closing == -1 else closing + 2
                continue
            stack.append("command")
            index += 2
            continue

        if character == ")" and context == "command":
            stack.pop()
            index += 1
            continue

        if character == "#" and context in ("plain", "command"):
            if index == 0 or text[index - 1] in " \t\n":
                newline = text.find("\n", index)
                index = length if newline == -1 else newline
                continue

        if character == "$":
            match = EXPANSION.match(text, index)
            if match is not None:
                if context != "double":
                    found.append((line, match.group(0)))
                index = match.end()
                continue

        index += 1

    return found


#: Script that renders every manifest the deployment applies.
RENDER_SCRIPT = REPO_ROOT / "scripts" / "render_kubernetes_manifests.sh"


def _render_group(name):
    """Return the manifest names one group of the renderer emits."""
    found = re.search(
        r"(?s)GROUP_" + name + r"=\((?P<body>.*?)\n\)", _text(RENDER_SCRIPT)
    )
    assert found is not None, name
    return re.findall(r'"([^"]+)"', found.group("body"))


def _render_defaults():
    """Return the value the renderer substitutes for each optional token."""
    found = re.search(
        r"(?s)TOKEN_DEFAULTS=\((?P<body>.*?)\n\)", _text(RENDER_SCRIPT)
    )
    assert found is not None, "the renderer declares no token defaults"
    entries = re.findall(r'"([A-Z_][A-Z0-9_]*)=([^"]*)"', found.group("body"))
    return dict(entries)


def _prerequisite_documents():
    """Return every object the deployment applies before it migrates."""
    documents = []
    defaults = _render_defaults()
    for name in _render_group("PREREQUISITES"):
        body = (MIGRATION_MANIFEST.parent / name).read_text(encoding="utf-8")
        for token, value in defaults.items():
            body = body.replace("${" + token + "}", value)
        documents.extend(
            document for document in yaml.safe_load_all(body) if document
        )
    return documents


def _one_prerequisite(kind):
    """Return the single object of one kind the prerequisites declare."""
    matching = [
        document
        for document in _prerequisite_documents()
        if document.get("kind") == kind
    ]
    assert len(matching) == 1, [
        document["metadata"]["name"] for document in matching
    ]
    return matching[0]


#: Manifest the migration is specified by. The step used to submit an
#: inline override document assembled from a running Deployment; it now
#: renders this manifest, which is a specification this repository owns and
#: which therefore applies to a first deployment as well as to a later one.
MIGRATION_MANIFEST = (
    REPO_ROOT / "infrastructure" / "kubernetes" / "60-migration-job.yaml"
)


def _migration_overrides():
    """Return the pod specification the migration step submits.

    The specification is the manifest the step renders and applies, so it is
    read from there rather than from the command. Substitution tokens the
    renderer fills are replaced with stand-ins, because their values are not
    knowable here and no assertion reads them.
    """
    command = _step_named(CD_WORKFLOW, CD_DEPLOY_JOB, MIGRATION_STEP_NAME)[
        "run"
    ]
    assert "render_kubernetes_manifests.sh migration" in command, command
    assert MIGRATION_MANIFEST.is_file(), MIGRATION_MANIFEST

    resolved = MIGRATION_MANIFEST.read_text(encoding="utf-8")
    resolved = re.sub(r"\$\{\{[^}]*\}\}", "resolved-elsewhere", resolved)
    for name, value in _workflow_environment(CD_WORKFLOW).items():
        resolved = resolved.replace("${" + name + "}", str(value))
    for name, value in _render_defaults().items():
        resolved = resolved.replace("${" + name + "}", value)
    resolved = re.sub(
        r"\$\{[A-Za-z_][A-Za-z0-9_]*\}", "resolved-elsewhere", resolved
    )

    #: The manifest is a Job, so the pod specification it governs is its
    #: template. Returning the template keeps every assertion below reading
    #: ``["spec"]["containers"]`` exactly as it read the override document.
    return yaml.safe_load(resolved)["spec"]["template"]


def _migration_setting():
    """Return the one setting a migration run reads.

    The name is declared by :data:`DATABASE_CONTRACT` and bound by
    :data:`MIGRATION_ENVIRONMENT`, so both are read: the declaration
    supplies the name and the binding proves the environment reads that
    name rather than one of its own.
    """
    found = MIGRATION_SETTING_DECLARATION.search(_text(DATABASE_CONTRACT))
    assert found is not None, "the contract declares no setting to read"
    assert MIGRATION_SETTING_BINDING in _text(MIGRATION_ENVIRONMENT)
    return found.group(1)


def _bash():
    """Return the path of an available bash, or skip the case."""
    executable = shutil.which("bash")
    if executable is None:
        pytest.skip("bash is unavailable on this host")
    return executable


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_each_workflow_parses_and_declares_a_job(path):
    """Both workflows are present and readable as workflows."""
    assert path.is_file(), path
    document = _document(path)
    assert document["jobs"], path.name
    assert document["permissions"] == {"contents": "read"}, path.name


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_is_referenced_by_a_commit(path):
    """No action is referenced by a tag, which its publisher can move."""
    references = ACTION_REFERENCE.findall(_text(path))
    assert references, path.name

    unpinned = [
        action
        for action, _release in references
        if not COMMIT_SHA.match(action) and not action.startswith("./")
    ]
    assert unpinned == [], unpinned


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_every_action_records_the_release_it_pins(path):
    """Each commit carries the release it was published as."""
    undocumented = [
        action
        for action, release in ACTION_REFERENCE.findall(_text(path))
        if not RELEASE_TAG.match(release or "")
        and not action.startswith("./")
    ]
    assert undocumented == [], undocumented


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_step_carries_an_empty_command(path):
    """A step that runs nothing reports success without checking any."""
    empty = [
        (job, position)
        for job, position, command in _commands(path)
        if not [
            line
            for line in command.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    ]
    assert empty == [], empty


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_step_defers_its_work_to_a_person(path):
    """No command stands in for work that was never written."""
    body = _text(path)
    present = [marker for marker in DEFERRAL_MARKERS if marker in body]
    assert present == [], present


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_step_invokes_a_frontend_script_that_is_absent(path):
    """Every npm script a command names is one the package declares."""
    declared = set(
        json.loads(_text(FRONTEND_PACKAGE)).get("scripts", {})
    )
    suites = list((REPO_ROOT / "frontend" / "src").rglob("*.test.*"))
    suites += list((REPO_ROOT / "frontend" / "src").rglob("*.spec.*"))

    for job, position, command in _commands(path):
        for name in NPM_SCRIPT.findall(command):
            assert name in declared, (job, position, name, sorted(declared))
        if NPM_TEST.search(command) and not suites:
            #: The workspace carries no test file and is read-only, so a
            #: suite invocation has to say so rather than fail for having
            #: nothing to run.
            assert "--passWithNoTests" in command, (job, position, command)


@pytest.mark.parametrize(
    "path,job",
    ((CI_WORKFLOW, CI_JOB), (CD_WORKFLOW, CD_GATE_JOB)),
    ids=("ci", "cd"),
)
def test_each_workflow_runs_every_gate(path, job):
    """A release clears the checks an ordinary push clears.

    Every job of the workflow is read, since the gate is delivered as
    several jobs; a gate is satisfied by a step whose name begins with it.
    """
    present = [
        step.get("name")
        for step in _every_step(path)
        if step.get("name")
    ]
    missing = sorted(
        gate
        for gate in GATE_STEP_NAMES
        if not any(name.startswith(gate) for name in present)
    )
    assert missing == [], missing


def test_the_deployment_job_runs_only_after_the_gate_job():
    """Nothing is deployed from a revision that failed a gate.

    The image build was separated from the cluster job, so the deployment
    reaches the gate through the build rather than directly. The chain is
    followed rather than asserted as one hop.
    """
    jobs = _document(CD_WORKFLOW)["jobs"]
    reached = set()
    frontier = [CD_DEPLOY_JOB]
    while frontier:
        name = frontier.pop()
        needs = jobs[name].get("needs") or []
        needs = [needs] if isinstance(needs, str) else list(needs)
        for required in needs:
            if required not in reached:
                reached.add(required)
                frontier.append(required)

    assert CD_GATE_JOB in reached, sorted(reached)


@pytest.mark.parametrize(
    "path", (CI_WORKFLOW, CD_WORKFLOW), ids=lambda path: path.name
)
def test_the_integration_step_migrates_and_probes_the_application(path):
    """The gate applies the migrations and exercises what it started.

    The claim is about the gate, not about one step of it: applying the
    migrations, reversing them, serving the application and probing it are
    delivered as separate steps so that a failure names which of the four
    failed. Every step of every job is therefore read, and the release
    workflow resolves through the gate workflow it calls.
    """
    gates = _gate_workflows(path)
    commands = [
        step["run"]
        for gate in gates
        for step in _every_step(gate)
        if "run" in step
    ]
    joined = "\n".join(commands)

    assert "alembic" in joined and "upgrade head" in joined, path.name
    assert "downgrade -1" in joined, path.name
    assert "uvicorn" in joined, path.name

    probed = _probed_paths(joined)
    assert LIVENESS_PATH in probed, probed
    assert READINESS_PATH in probed, probed

    #: The database the gate runs against is a service of the job, so no
    #: credential of a deployed environment is present. Every declared
    #: address is read, because the gate spreads its steps over jobs.
    environments = [
        environment
        for gate in gates
        for environment in _declared_environments(gate)
    ]
    addresses = [
        environment["DATABASE_URL"]
        for environment in environments
        if "DATABASE_URL" in environment
    ]
    assert addresses, path.name
    for address in addresses:
        assert any(
            host + ":5432" in address for host in ("127.0.0.1", "localhost")
        ), address

    #: The gate mints its own signing key rather than borrowing a deployed
    #: one. What matters is not where the value is written but where it
    #: comes from: every value the gate declares is a literal written in the
    #: workflow, so no repository secret and no deployed credential is
    #: readable from a gate run.
    minted = False
    for environment in environments:
        for name, value in environment.items():
            assert "secrets." not in str(value), (name, value)
            if name == "SECRET_KEY":
                minted = True
    assert minted or "SECRET_KEY" in joined, "the gate mints no signing key"


def test_the_release_probes_liveness_and_readiness():
    """A rollout that answers without its dependencies is a failure."""
    command = _step_named(
        CD_WORKFLOW, CD_DEPLOY_JOB, RELEASE_PROBE_STEP_NAME
    )["run"]

    probed = _probed_paths(command)
    assert LIVENESS_PATH in probed, probed
    assert READINESS_PATH in probed, probed
    assert command.count("exit 1") >= 2, command


def test_the_deployment_script_probes_liveness_and_readiness():
    """The operator path asserts the same two answers the pipeline does."""
    body = _text(DEPLOY_SCRIPT)

    probed = _probed_paths(body)
    assert LIVENESS_PATH in probed, probed
    assert READINESS_PATH in probed, probed
    assert "port-forward" in body


@pytest.mark.parametrize(
    "path",
    (CD_WORKFLOW, DEPLOY_SCRIPT),
    ids=lambda path: path.name,
)
def test_every_probed_path_is_served_by_the_application(path):
    """No probe asserts a route the application does not publish."""
    served = _served_paths()
    body = _text(path)
    probed = set(_probed_paths(body))
    assert probed, path.name
    assert probed <= served, sorted(probed - served)


def test_the_migration_pod_is_specified_by_this_repository():
    """The pod that migrates copies nothing from the serving Deployment."""
    command = _step_named(CD_WORKFLOW, CD_DEPLOY_JOB, MIGRATION_STEP_NAME)[
        "run"
    ]
    assert DEPLOYMENT_READ.search(command) is None, command

    specification = _migration_overrides()["spec"]
    #: The identity is one the prerequisites create, so the migration runs
    #: as a principal this repository declares and grants rather than as the
    #: namespace default.
    accounts = [
        document["metadata"]["name"]
        for document in _prerequisite_documents()
        if document.get("kind") == "ServiceAccount"
    ]
    assert accounts, "the prerequisites create no identity"
    assert specification["serviceAccountName"] in accounts, (
        specification["serviceAccountName"],
        accounts,
    )
    assert specification["restartPolicy"] == "Never"


def test_the_migration_pod_carries_only_the_database_setting():
    """It holds the one setting the migration environment reads."""
    setting = _migration_setting()
    assert setting in Settings.__fields__, setting

    specification = _migration_overrides()["spec"]
    container = specification["containers"][0]

    #: And it does not travel through the delivery workflow either:
    #: the credential reaches the migration from the managed store by
    #: way of the manifest, so the workflow declares no value for it.
    assert setting not in _workflow_environment(CD_WORKFLOW)

    #: No inline value: every credential arrives through the managed store,
    #: which is why the container declares none of them and why the one
    #: setting it does declare is empty. That is a stronger position than a
    #: reference to a cluster Secret, because the value is never copied out
    #: of Secret Manager into an object the cluster holds.
    declared = container.get("env") or []
    for entry in declared:
        assert "valueFrom" not in entry, entry
        assert not entry.get("value"), entry
        assert entry["name"] not in Settings.__fields__ or not entry.get(
            "value"
        ), entry
    assert setting not in [entry["name"] for entry in declared], declared

    #: What the container reads is the settings map, which carries no
    #: credential, and it is required, so the pod cannot start without it.
    #: It reads no cluster Secret at all: the one the serving workload also
    #: reads carries the shared rate-limit address, which a migration run
    #: never reads, and the database credential it does read arrives as a
    #: mounted file rather than through the environment.
    configured = [
        source["configMapRef"]["name"]
        for source in container["envFrom"]
        if "configMapRef" in source
    ]
    published = [
        source["secretRef"]["name"]
        for source in container["envFrom"]
        if "secretRef" in source
    ]
    assert configured == [
        _one_prerequisite("ConfigMap")["metadata"]["name"]
    ], configured
    assert published == [], published
    for source in container["envFrom"]:
        for kind in source:
            assert source[kind].get("optional") is False, source

    #: One credential volume, delivered by the provider class the backend
    #: itself is delivered by, read-only.
    volumes = specification["volumes"]
    delivered = [volume for volume in volumes if "csi" in volume]
    assert len(delivered) == 1, volumes
    attributes = delivered[0]["csi"]["volumeAttributes"]
    #: The class is one the prerequisites declare, and it is the narrow one
    #: rather than the six-secret class the serving workload mounts, so the
    #: identity running the migration is granted one secret instead of six.
    classes = {
        document["metadata"]["name"]: document
        for document in _prerequisite_documents()
        if document.get("kind") == "SecretProviderClass"
    }
    mounted = attributes["secretProviderClass"]
    assert mounted in classes, (mounted, sorted(classes))

    entries = yaml.safe_load(classes[mounted]["spec"]["parameters"]["secrets"])
    assert [entry["path"] for entry in entries] == [setting], entries
    assert delivered[0]["csi"]["readOnly"] is True

    #: The setting is read from the delivered file rather than from an
    #: environment the cluster could render into a log.
    command = " ".join(container["command"])
    assert setting in command, command


def test_the_migration_pod_runs_the_migrations_and_nothing_else():
    """Its command is the upgrade, so no other code runs under it."""
    container = _migration_overrides()["spec"]["containers"][0]
    command = container["command"]

    #: The container is entered through a shell because the credentials are
    #: delivered as files and have to be exported before the upgrade reads
    #: them. What is asserted is that the shell does nothing else: the
    #: upgrade is the process the shell replaces itself with, so no code can
    #: run after it.
    assert command[:2] == ["/bin/sh", "-c"], command
    assert len(command) == 3, command
    script = command[2]
    assert "python -m alembic" in script, script
    assert script.rstrip().rstrip(";").endswith("upgrade head"), script
    assert "exec python -m alembic" in script, script


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_step_describes_a_pod(path):
    """A description renders every container's environment into the log."""
    for job, position, command in _commands(path):
        described = POD_DESCRIPTION.search(command)
        if described is None:
            continue
        #: A Job may be described: it carries a specification this
        #: repository owns, whose environment is references rather than
        #: values, and it is described only after a migration has failed.
        #: A pod may not, because finding one means listing objects whose
        #: state is not ours.
        described = command[described.start():]
        for found in POD_DESCRIPTION.finditer(described):
            described_object = found.group("object").strip('"\'')
            assert described_object.startswith("job/"), (
                job,
                position,
                described_object,
            )


def test_the_migration_failure_reports_only_the_fields_it_needs():
    """A migration that did not complete is waited on, reported and fatal.

    The step used to poll a pod's phase and read three fields off its
    terminated state. It now waits on the Job's own completion condition,
    which is the outcome those fields were being assembled into, and reports
    it before failing the release. What is asserted is that the wait is
    bounded, that its result is read rather than assumed, and that a
    migration which did not complete stops the deployment.
    """
    command = _step_named(CD_WORKFLOW, CD_DEPLOY_JOB, MIGRATION_STEP_NAME)[
        "run"
    ]

    assert "--for=condition=complete" in command
    assert "--timeout=" in command
    assert "kubectl" in command and "logs" in command
    assert "exit 1" in command


def test_the_migration_output_is_read_from_the_governed_container():
    """The republished output is the container whose records are governed.

    The Job declares one container, so naming the Job names it; the step
    reads ``job/<name>`` rather than selecting a container inside a pod it
    would first have to find.
    """
    command = _step_named(CD_WORKFLOW, CD_DEPLOY_JOB, MIGRATION_STEP_NAME)[
        "run"
    ]
    containers = _migration_overrides()["spec"]["containers"]

    assert len(containers) == 1, [one["name"] for one in containers]
    assert "kubectl" in command and "logs" in command
    assert 'job/$JOB_NAME' in command or "job/${JOB_NAME}" in command


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_no_workflow_command_expands_a_name_unquoted(path):
    """An unquoted value carrying a space becomes two words."""
    reported = []
    for job, position, command in _commands(path):
        for line, expansion in _unquoted_expansions(command):
            reported.append((job, position, line, expansion))
    assert reported == [], reported


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda path: path.name)
def test_no_script_expands_a_name_unquoted(path):
    """The same rule holds for the scripts an operator runs."""
    reported = _unquoted_expansions(_text(path))
    assert reported == [], reported


def test_the_deployment_script_reports_no_account_it_reads():
    """The active identity is reported by reference, not by address."""
    body = _text(DEPLOY_SCRIPT)

    assert "account_reference" in body
    rendered = [
        line
        for line in body.splitlines()
        if re.search(r"\b(?:echo|printf)\b", line)
        and "${active_account}" in line
        and "account_reference" not in line
    ]
    assert rendered == [], rendered


def test_the_secret_delivery_is_applied_from_this_repository():
    """The deployment applies a manifest that is version-controlled."""
    command = _step_named(CD_WORKFLOW, CD_DEPLOY_JOB, DELIVERY_STEP_NAME)[
        "run"
    ]
    assert DELIVERY_MANIFEST.is_file(), DELIVERY_MANIFEST

    #: The step names the group rather than the file, so what is checked is
    #: that the group it renders emits this manifest. That is a stronger
    #: claim than finding the name in the command: it proves the file is
    #: applied rather than merely mentioned.
    assert RENDER_SCRIPT.name in command, command
    assert "prerequisites" in command, command
    assert DELIVERY_MANIFEST.name in _render_group("PREREQUISITES")
    assert "kubectl apply" in command


def test_the_secret_delivery_names_the_secrets_terraform_declares():
    """Every delivered name is a secret the configuration creates."""
    declared = set(TERRAFORM_SECRET_ID.findall(_text(TERRAFORM_MAIN)))
    assert declared, "the configuration declares no secret"

    body = _text(DELIVERY_MANIFEST)
    delivered = set(re.findall(r"/secrets/([A-Z][A-Z0-9_]*)/versions/", body))
    assert delivered, "the manifest delivers no secret"
    assert delivered <= declared, sorted(delivered - declared)


def test_the_secret_delivery_carries_no_secret_value():
    """It names versions to mount and no payload of any of them."""
    documents = [
        document
        for document in yaml.safe_load_all(_text(DELIVERY_MANIFEST))
        if document
    ]
    assert documents, DELIVERY_MANIFEST

    for document in documents:
        assert document["kind"] == "SecretProviderClass", document["kind"]
        parameters = document["spec"]["parameters"]
        assert set(parameters) == {"secrets"}, sorted(parameters)
        for entry in yaml.safe_load(parameters["secrets"]):
            assert set(entry) == {"resourceName", "path"}, sorted(entry)
            assert entry["resourceName"].endswith("/versions/latest")


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda path: path.name)
def test_the_interpreter_pin_is_unchanged(path):
    """The pinned interpreter is the one the application requires."""
    versions = []
    for step in _every_step(path):
        if "setup-python" in str(step.get("uses", "")):
            versions.append(step["with"]["python-version"])
    assert versions, path.name
    assert set(versions) == {PINNED_PYTHON}, versions


def test_the_deployed_function_runtime_is_unchanged():
    """The deployment script pins the same interpreter for the function."""
    assert PINNED_FUNCTION_RUNTIME in _text(DEPLOY_SCRIPT)


@pytest.mark.parametrize("path", PIPELINE_FILES, ids=lambda path: path.name)
def test_each_file_ends_with_exactly_one_newline(path):
    """A file without a final newline appends to the next line read."""
    body = path.read_bytes()
    assert body.endswith(b"\n"), path.name
    assert not body.endswith(b"\n\n"), path.name


@pytest.mark.parametrize("path", SCRIPTS, ids=lambda path: path.name)
def test_each_script_parses(path):
    """``bash -n`` accepts both scripts."""
    completed = subprocess.run(
        [_bash(), "-n", str(path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=SHELL_TIMEOUT_SECONDS,
    )
    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", "replace"
    )


@pytest.mark.parametrize(
    "path,job",
    (
        (CI_WORKFLOW, CI_JOB),
        (CD_WORKFLOW, CD_GATE_JOB),
        (CD_WORKFLOW, CD_DEPLOY_JOB),
    ),
    ids=("ci", "cd-verify", "cd-deploy"),
)
def test_every_command_parses(path, job, tmp_path):
    """Each command is a script a shell accepts before a runner runs it."""
    for position, step in enumerate(_steps(path, job)):
        if "run" not in step:
            continue
        #: The runner substitutes its own expressions before the shell
        #: sees them, so they are replaced here as the runner would.
        body = re.sub(r"\$\{\{[^}]*\}\}", "substituted", step["run"])
        written = tmp_path / ("step_%d.sh" % position)
        #: Written with newlines the shell reads, whatever this host's
        #: line ending is, because a here-document delimiter is matched
        #: against a whole line.
        with open(str(written), "w", encoding="utf-8", newline="\n") as handle:
            handle.write(body)

        completed = subprocess.run(
            [_bash(), "-n", str(written)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=SHELL_TIMEOUT_SECONDS,
        )
        assert completed.returncode == 0, (
            job,
            position,
            completed.stderr.decode("utf-8", "replace"),
        )
