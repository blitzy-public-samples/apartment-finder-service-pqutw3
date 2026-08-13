"""Checks that the release definitions name things that exist.

Neither the deployment script nor the workflows can be executed from
this test process: there is no Docker engine, no cluster and no cloud
project. Every property below is therefore asserted against the
declaration, which is the layer the review found wrong -- each command
named a Dockerfile, a build context, a Kubernetes workload or a cloud
resource that does not exist anywhere in this repository.

What is asserted:

* every ``docker build`` in ``.github/workflows/cd.yml`` and
  ``scripts/deploy.sh`` names a Dockerfile that exists and a context
  directory that exists, and the context carries the paths that
  Dockerfile copies
* both release paths tag, push and roll out the same image names, under
  the Artifact Registry prefix ``infrastructure/terraform/outputs.tf``
  publishes, and neither names the legacy registry
* every Kubernetes workload either path addresses is one the other also
  addresses, so the two do not disagree about what is deployed
* the Cloud Function either path deploys is the one
  ``infrastructure/terraform/main.tf`` declares
* the regional cluster is addressed by region, never by zone
* the schema migration is issued before any image is flipped, in both
  paths
* neither path grants nor tolerates a public invoker on the function,
  and each asserts the effective policy after deploying
* the Python runtime pin is present and unaltered at each of its sites
* the generated cloud credential file is ignored by every ignore file
  and removed unconditionally

``infrastructure/terraform/main.tf`` is the authority for the function
name and the runtime pin, the two Dockerfiles are the authority for what
each build context must carry, and ``cd.yml`` is the authority for the
workload names. A change to any of them is compared against this file
rather than against a second copy of it.
"""

import re

import pytest
import yaml
from conftest import REPO_ROOT

#: Release definitions under test.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy.sh"

#: Terraform configuration the release definitions must agree with.
TERRAFORM_MAIN = REPO_ROOT / "infrastructure" / "terraform" / "main.tf"
TERRAFORM_OUTPUTS = REPO_ROOT / "infrastructure" / "terraform" / "outputs.tf"

#: Container definitions each build must name.
DOCKER_DIRECTORY = REPO_ROOT / "infrastructure" / "docker"
DOCKERFILES = {
    "frontend": DOCKER_DIRECTORY / "Dockerfile.frontend",
    "backend": DOCKER_DIRECTORY / "Dockerfile.backend",
}

#: Build context each image is built from, relative to the repository
#: root.
BUILD_CONTEXTS = {
    "frontend": REPO_ROOT / "frontend",
    "backend": REPO_ROOT / "backend",
}

#: Paths each build context must carry for its image to build. The
#: frontend image installs from a lock file and builds from ``src``; the
#: backend image installs from its manifest and runs migrations.
CONTEXT_REQUIREMENTS = {
    "frontend": ("package.json", "package-lock.json", "src"),
    "backend": ("requirements.txt", "alembic.ini", "migrations", "app"),
}

#: Kubernetes Deployment names both release paths address.
WORKLOADS = ("frontend", "backend")

#: Registry host no release definition may name.
LEGACY_REGISTRY = "gcr.io"

#: Environment name holding the Artifact Registry image prefix.
IMAGE_PREFIX_VARIABLE = "IMAGE_PREFIX"

#: Terraform output publishing that prefix.
IMAGE_PREFIX_OUTPUT = "artifact_registry_image_prefix"

#: Invoker role neither release path may grant to a public principal.
INVOKER_ROLE = "roles/cloudfunctions.invoker"

#: Public principals that role may never name.
PUBLIC_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")

#: Runtime pin, byte-exact, at each site that carries it.
RUNTIME_PINS = {
    TERRAFORM_MAIN: '  runtime     = "python39"',
    DEPLOY_SCRIPT: "--runtime python39",
    CI_WORKFLOW: "python-version: '3.9'",
}

#: Credential file the authentication action writes into the workspace.
GENERATED_CREDENTIAL = "gha-creds-*.json"

#: Every ignore file that must exclude it.
IGNORE_FILES = (
    REPO_ROOT / ".gitignore",
    REPO_ROOT / ".dockerignore",
    REPO_ROOT / "backend" / ".dockerignore",
    REPO_ROOT / "frontend" / ".dockerignore",
)

#: Marker no release definition may carry.
UNFINISHED_MARKER = "HUMAN ASSISTANCE NEEDED"

#: One ``docker build`` invocation, with its Dockerfile and its context.
BUILD_INVOCATION = re.compile(
    r"docker build\s*\\?\s*\n?\s*-f\s+(?P<dockerfile>[^\s\\]+)"
    r"[^\n]*(?:\\\s*\n[^\n]*)*?\s(?P<context>\.\/[A-Za-z0-9_./-]+)\s*$",
    re.MULTILINE,
)


def _cd_text():
    return CD_WORKFLOW.read_text(encoding="utf-8")


def _strip_comments(text):
    """Return the configuration with its ``#`` comment lines removed."""
    return "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )


def _deploy_text():
    return DEPLOY_SCRIPT.read_text(encoding="utf-8")


def _release_sources():
    return {"cd.yml": _cd_text(), "deploy.sh": _deploy_text()}


def _shell_tables(text):
    """Return every ``declare -A NAME=( [k]=v ... )`` mapping in a script."""
    tables = {}
    for match in re.finditer(
        r"declare\s+-A\s+(?P<name>[A-Z_]+)=\((?P<body>.*?)\n\)",
        text,
        re.DOTALL,
    ):
        tables[match.group("name")] = dict(
            re.findall(
                r'\["?(?P<key>[A-Za-z0-9_-]+)"?\]="(?P<value>[^"]*)"',
                match.group("body"),
            )
        )
    return tables


def _shell_lists(text):
    """Return every ``NAME=("a" "b")`` array in a script."""
    lists = {}
    for match in re.finditer(
        r"(?:readonly\s+)?(?P<name>[A-Z_]+)=\((?P<body>[^()]*?)\)", text
    ):
        items = re.findall(r'"([^"]*)"', match.group("body"))
        if items:
            lists.setdefault(match.group("name"), items)
    return lists


def _resolve_through_tables(value, text, key):
    """Resolve one ``${TABLE[${key}]}`` reference against its table."""
    match = re.fullmatch(
        r"\$\{(?P<table>[A-Z_]+)\[\$\{[a-z_]+\}\]\}", value
    )
    if match is None:
        return value
    table = _shell_tables(text).get(match.group("table"), {})
    return table.get(key, value)


def _shell_locals(text):
    """Return each ``name="value"`` assignment inside a script."""
    return dict(
        re.findall(r'(?m)^\s*(?:local\s+)?([a-z_]+)="([^"\n]*)"', text)
    )


def _resolve_path(value, text, key):
    """Resolve a build path written as an expansion to a repository path.

    A path may be an expansion of a local, whose own value expands a table
    entry, so both hops are followed and the repository-root prefix is
    dropped. The result is the path relative to the repository, which is
    what a literal invocation writes directly.
    """
    seen = 0
    while "${" in value and seen < 4:
        seen += 1
        simple = re.fullmatch(r'"?\$\{([a-z_]+)\}"?', value)
        if simple is not None:
            value = _shell_locals(text).get(simple.group(1), value)
            continue
        value = _resolve_through_tables(
            value.replace("${REPO_ROOT}/", ""), text, key
        )
        break
    return value.replace("${REPO_ROOT}/", "").strip('"')


def _builds(text):
    """Return the Dockerfile and context of each ``docker build``.

    A path may be written literally or read from a table the script
    declares, which is how one loop body builds every image. A table-driven
    invocation is expanded into one entry per declared workload, so the
    result is the same shape either way -- and a table naming the wrong
    Dockerfile for an image is still caught.
    """
    found = {}
    for match in BUILD_INVOCATION.finditer(text):
        found[match.group("dockerfile")] = match.group("context")

    #: A table-driven invocation writes one build for every workload, with
    #: the long flag and the paths held in the tables above it. Each one is
    #: expanded so a table naming the wrong Dockerfile for an image is
    #: still caught.
    for match in re.finditer(
        r"docker build\s*\\?\s*\n?\s*--file\s+(?P<dockerfile>\S+)"
        r"[^\n]*?\s(?P<context>\S+)\s*$",
        text,
        re.MULTILINE,
    ):
        for workload in _shell_lists(text).get("RELEASE_WORKLOADS", []):
            dockerfile = _resolve_path(
                match.group("dockerfile"), text, workload
            )
            context = _resolve_path(match.group("context"), text, workload)
            if not context.startswith("."):
                context = "./" + context
            found[dockerfile] = context
    return found


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_each_release_path_builds_two_images(label):
    builds = _builds(_release_sources()[label])
    assert len(builds) == len(DOCKERFILES), (
        f"{label} declares {sorted(builds)} rather than one build per image"
    )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_each_build_names_a_dockerfile_that_exists(label):
    for dockerfile in _builds(_release_sources()[label]):
        resolved = REPO_ROOT / dockerfile
        assert resolved.is_file(), (
            f"{label} builds with a missing {dockerfile}"
        )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_each_build_names_a_context_that_exists(label):
    for dockerfile, context in _builds(_release_sources()[label]).items():
        resolved = (REPO_ROOT / context.lstrip("./")).resolve()
        assert resolved.is_dir(), (
            f"{label} builds {dockerfile} from a missing context {context}"
        )


@pytest.mark.parametrize("image", sorted(DOCKERFILES))
def test_each_build_pairs_the_image_with_its_own_dockerfile(image):
    expected_dockerfile = (
        f"infrastructure/docker/{DOCKERFILES[image].name}"
    )
    expected_context = f"./{image}"
    for label, text in _release_sources().items():
        builds = _builds(text)
        assert builds.get(expected_dockerfile) == expected_context, (
            f"{label} does not build {expected_dockerfile} from "
            f"{expected_context}; it declares {builds}"
        )


def _frontend_build_arguments():
    """Returns the ``ARG`` names Dockerfile.frontend declares."""
    declared = re.findall(
        r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)",
        DOCKERFILES["frontend"].read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert declared, "Dockerfile.frontend declares no build argument"
    return sorted(declared)


def _passed_build_arguments(label, text):
    """Returns the frontend build-argument names one release path passes.

    A path either writes each ``--build-arg`` literally, or passes one per
    name in a table its build loop reads. Both forms resolve to the same
    kind of answer -- a set of names -- so a path is compared against the
    Dockerfile rather than against the other path's spelling.
    """
    literal = set(
        re.findall(r'--build-arg\s+"([A-Za-z_][A-Za-z0-9_]*)=', text)
    )
    if literal:
        return literal

    assert "--build-arg" in text, label
    table = re.search(
        r"WORKLOAD_BUILD_ARGUMENTS=\((?P<body>.*?)\n\)", text, re.S
    )
    assert table, label
    entry = re.search(
        r'\["frontend"\]="(?P<names>[^"]*)"', table.group("body")
    )
    assert entry, label
    return set(entry.group("names").split())


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_each_release_path_passes_every_frontend_build_argument(label):
    """Both paths supply every value the browser bundle is built with.

    The bundler inlines each ``REACT_APP_*`` value present at build time
    into the published bundle, so an argument a path does not pass is a
    bundle that cannot reach the API or open hosted checkout -- and docker
    accepts an absent argument without complaint, so nothing in the build
    itself reports it. One path passed both and the other passed none at
    all, which is the shape this asserts against: the Dockerfile is the
    authority for the list, and each path is checked against it rather
    than against the other.
    """
    text = _release_sources()[label]

    assert _passed_build_arguments(label, text) == set(
        _frontend_build_arguments()
    ), label


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_each_release_path_refuses_an_empty_frontend_build_value(label):
    """Both paths fail closed when a build value is not populated.

    Passing the argument is not enough: docker accepts an empty value, so
    the bundle is published and fails for an end user rather than for the
    pipeline. Each path is asserted to test emptiness by name, over the
    same set of names it passes to the build.
    """
    text = _release_sources()[label]

    assert _passed_build_arguments(label, text), label
    assert re.search(r'-z\s+"\$\{value(?::-)?\}"', text), label
    assert "for name in " in text, label


def test_the_frontend_build_values_are_repository_variables():
    """The workflow reads both from the variable context, not secrets.

    Both values are inlined into a published bundle, so neither is a
    secret and both are documented as repository variables. Reading one
    from the secrets context and the other from the variables context is
    what left the bundle built with an empty client identifier while the
    backend configuration carried a populated one, so the same context
    supplies both here -- and the PayPal client identifier is read from
    the identical expression the manifest rendering reads it from, so the
    bundle and the backend cannot name two different applications.
    """
    text = _cd_text()
    client_identifier = "${{ vars.PAYPAL_CLIENT_ID }}"

    assert "secrets.PAYPAL_CLIENT_ID" not in text
    assert "secrets.REACT_APP_API_BASE_URL" not in text
    assert "${{ vars.REACT_APP_API_BASE_URL }}" in text
    assert text.count(client_identifier) >= 2, text.count(
        client_identifier
    )


@pytest.mark.parametrize("image", sorted(CONTEXT_REQUIREMENTS))
def test_each_build_context_carries_the_paths_its_image_needs(image):
    context = BUILD_CONTEXTS[image]
    for required in CONTEXT_REQUIREMENTS[image]:
        assert (context / required).exists(), (
            f"the {image} build context is missing {required}"
        )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_no_release_path_names_the_legacy_registry(label):
    text = _release_sources()[label]
    assert LEGACY_REGISTRY not in text, (
        f"{label} still names {LEGACY_REGISTRY}"
    )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_every_image_reference_uses_the_published_prefix(label):
    text = _release_sources()[label]
    #: The prefix may be tagged against directly or through a name the
    #: source assigns from it, which is how one value is read once and used
    #: for every tag. Every such alias is resolved, so a tag against some
    #: other registry is still caught.
    #: A tag may name the published prefix directly or name a value the
    #: source composes from the same parts the prefix is composed from --
    #: the registry host, the project and the repository. Both are
    #: accepted, and a name that is composed must be composed from all
    #: three, so a tag against some other registry is still caught.
    aliases = {IMAGE_PREFIX_VARIABLE}
    for alias, value in re.findall(
        r'(?m)^\s*(?:export\s+|readonly\s+)?([A-Z_]+)="?([^"\n]*)', text
    ):
        if value.startswith("$") and value.strip("${}") in aliases:
            aliases.add(alias)
        elif "docker.pkg.dev" in value and "PROJECT_ID" in value:
            aliases.add(alias)
    for image in DOCKERFILES:
        assert any(
            f"{alias}}}/{image}:" in text or f"{alias}/{image}:" in text
            for alias in aliases
        ), (
            f"{label} tags {image} outside the published registry prefix; "
            f"the prefix reaches it through {sorted(aliases)}"
        )


def test_the_published_prefix_is_declared_by_terraform():
    outputs = TERRAFORM_OUTPUTS.read_text(encoding="utf-8")
    assert f'output "{IMAGE_PREFIX_OUTPUT}"' in outputs, (
        "the Artifact Registry prefix the release paths tag against is not "
        "published by infrastructure/terraform/outputs.tf"
    )
    main = TERRAFORM_MAIN.read_text(encoding="utf-8")
    assert 'resource "google_artifact_registry_repository"' in main, (
        "no Artifact Registry repository is declared for the images the "
        "release paths push"
    )


@pytest.mark.parametrize("workload", WORKLOADS)
@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_each_release_path_rolls_out_every_workload(workload, label):
    text = _release_sources()[label]

    #: A source may name each Deployment or iterate the workloads it
    #: declares. Both are accepted, and the declared list must be exactly
    #: the workloads this claim is about, so iterating cannot skip one.
    if f"deployment/{workload}" in text:
        return
    declared = _shell_lists(text).get("RELEASE_WORKLOADS")
    assert declared is not None, (
        f"{label} never addresses deployment/{workload}"
    )
    assert sorted(declared) == sorted(WORKLOADS), declared
    assert 'deployment/${workload}' in text, (
        f"{label} never addresses deployment/{workload}"
    )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_no_release_path_addresses_an_undeclared_workload(label):
    text = _release_sources()[label]
    addressed = set(re.findall(r"deployment/([A-Za-z0-9-]+)", text))
    if r"deployment/${workload}" in text:
        addressed |= set(_shell_lists(text).get("RELEASE_WORKLOADS", []))
    assert addressed == set(WORKLOADS), (
        f"{label} addresses {sorted(addressed)} rather than "
        f"{sorted(WORKLOADS)}"
    )


def test_the_deployed_function_is_the_one_terraform_declares():
    main = TERRAFORM_MAIN.read_text(encoding="utf-8")
    block = re.search(
        r'resource "google_cloudfunctions_function" "function" \{(.*?)\n\}',
        main,
        re.DOTALL,
    )
    assert block, "no first-generation Cloud Function is declared"
    declared = re.search(r'name\s*=\s*"([^"]+)"', block.group(1))
    if declared is None:
        #: The name comes from a declared input rather than a literal, so
        #: one value governs Terraform and the script. Its default is read
        #: from the variable.
        reference = re.search(r"name\s*=\s*var\.(\w+)", block.group(1))
        assert reference, "the declared function carries no name"
        variable = re.search(
            r'(?s)variable\s+"' + reference.group(1) + r'"\s*\{(.*?)\n\}',
            (TERRAFORM_MAIN.parent / "variables.tf").read_text(
                encoding="utf-8"
            ),
        )
        assert variable, reference.group(1)
        declared = re.search(r'default\s*=\s*"([^"]+)"', variable.group(1))
        assert declared, "the function input carries no default name"

    outputs = TERRAFORM_OUTPUTS.read_text(encoding="utf-8")
    assert 'output "cloud_function_name"' in outputs, (
        "the function name the release paths deploy is not published by "
        "infrastructure/terraform/outputs.tf"
    )
    for label, text in _release_sources().items():
        assert "CLOUD_FUNCTION_NAME" in text, (
            f"{label} does not take the function name from the published "
            f"output; the declared name is {declared.group(1)}"
        )
        assert "function-name" not in text, (
            f"{label} still deploys the placeholder name function-name "
            f"rather than {declared.group(1)}"
        )
        assert "./functions" not in text, (
            f"{label} still reads the function source from ./functions, "
            "which this repository does not carry"
        )


def test_the_regional_cluster_is_addressed_by_region():
    text = _cd_text()
    assert "--region " in text, "cd.yml does not address the cluster by region"
    assert "--zone " not in text, (
        "cd.yml addresses a regional cluster by zone"
    )
    main = TERRAFORM_MAIN.read_text(encoding="utf-8")
    cluster = re.search(
        r'resource "google_container_cluster" "primary" \{(.*?)\n\}',
        main,
        re.DOTALL,
    )
    assert cluster and "location = var.region" in cluster.group(1), (
        "the cluster is no longer regional, so the region flag is wrong"
    )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_the_migration_is_issued_before_any_image_is_flipped(label):
    text = _release_sources()[label]
    migration = text.index("alembic")

    #: An image reaches a Deployment either by being set on the running
    #: object or by applying a manifest that already carries it. The second
    #: is what this repository does in the workflow, because the manifest
    #: carries the published digest; the script does the first. Whichever
    #: is used, the migration must precede it.
    #: The apply carries a request deadline, so the construct is matched on
    #: its stem rather than on a fixed flag order: `kubectl apply` reading
    #: from standard input, whatever bounds it also carries.
    flips = [
        match.start()
        for match in re.finditer(
            r"kubectl set image|kubectl apply(?:\s+--\S+)*\s+-f\s+-", text
        )
    ]
    assert flips, f"{label} never rolls an image out"
    assert migration < max(flips), (
        f"{label} flips the image before applying the schema migration"
    )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_no_release_path_grants_a_public_invoker(label):
    text = _release_sources()[label]
    for line in text.splitlines():
        if "add-iam-policy-binding" not in line:
            continue
        for principal in PUBLIC_PRINCIPALS:
            assert principal not in line, (
                f"{label} grants {principal} an IAM binding"
            )
    assert "--allow-unauthenticated" not in text, (
        f"{label} still deploys the function with anonymous invocation"
    )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_each_release_path_asserts_the_effective_invoker_policy(label):
    text = _release_sources()[label]
    assert "get-iam-policy" in text, (
        f"{label} never reads the function's effective IAM policy"
    )
    assert INVOKER_ROLE in text, (
        f"{label} never names {INVOKER_ROLE} when checking the policy"
    )
    for principal in PUBLIC_PRINCIPALS:
        assert principal in text, (
            f"{label} does not test the effective policy for {principal}"
        )


def test_the_authoritative_invoker_binding_is_declared():
    main = TERRAFORM_MAIN.read_text(encoding="utf-8")
    assert 'resource "google_cloudfunctions_function_iam_binding"' in main, (
        "the invoker role is not managed authoritatively, so a public "
        "member already on the role would survive an apply"
    )
    additive = 'resource "google_cloudfunctions_function_iam_member"'
    assert additive not in main, (
        "an additive invoker member remains, which cannot remove a public "
        "principal"
    )


@pytest.mark.parametrize("path", sorted(RUNTIME_PINS, key=str))
def test_the_runtime_pin_is_unaltered(path):
    text = path.read_text(encoding="utf-8")
    assert RUNTIME_PINS[path] in text, (
        f"{path.name} no longer carries the runtime pin "
        f"{RUNTIME_PINS[path]!r}"
    )


def test_the_generated_credential_file_is_ignored_everywhere():
    for path in IGNORE_FILES:
        text = path.read_text(encoding="utf-8")
        assert GENERATED_CREDENTIAL in text, (
            f"{path.name} does not ignore {GENERATED_CREDENTIAL}"
        )


def test_the_generated_credential_file_is_removed_unconditionally():
    document = yaml.safe_load(_cd_text())
    removals = [
        step
        for job in document["jobs"].values()
        for step in job.get("steps", [])
        if GENERATED_CREDENTIAL in (step.get("run") or "")
    ]
    assert removals, "cd.yml never removes the generated credential file"
    for step in removals:
        assert step.get("if") == "always()", (
            "the credential removal is skipped when an earlier step fails"
        )


@pytest.mark.parametrize("label", sorted(_release_sources()))
def test_no_release_path_carries_an_unfinished_marker(label):
    text = _release_sources()[label]
    assert UNFINISHED_MARKER not in text, (
        f"{label} still carries a {UNFINISHED_MARKER} block"
    )


def test_the_integration_gate_runs_the_application():
    document = yaml.safe_load(CI_WORKFLOW.read_text(encoding="utf-8"))
    steps = [
        step
        for job in document["jobs"].values()
        for step in job.get("steps", [])
    ]
    #: The gate applies the migrations, reverses them, starts the
    #: application and probes it as separate steps across separate jobs, so
    #: a failure names which of them failed. Every step is read, and each
    #: element below must be invoked by one of them.
    integration = [step for step in steps if "run" in step]
    assert integration, "ci.yml declares no integration step"
    body = "\n".join(step["run"] for step in integration)
    for required in (
        "alembic -c backend/alembic.ini upgrade head",
        "alembic -c backend/alembic.ini downgrade -1",
        'python -c "import backend.app.main"',
        "uvicorn backend.app.main:app",
        "/health",
        "/health/ready",
        "/listings/",
        "/auth/login",
    ):
        assert required in body, (
            f"the integration gate does not exercise {required}"
        )
    for step in integration:
        assert "continue-on-error" not in str(step), (
            "the integration gate is softened"
        )
        body = step["run"].lstrip()
        if body.startswith("set -e"):
            continue
        #: A step whose whole body is one script invocation inherits that
        #: script's own failure handling, which is where it belongs.
        invoked = re.fullmatch(
            r"(?:bash|sh)\s+(?P<script>\S+\.sh)\s*", body
        )
        if invoked is None:
            #: A step running one command has nothing to fail between: its
            #: own exit status is the step's. What the flag protects
            #: against is a later command running after an earlier one
            #: failed, so only a step running more than one needs it.
            commands = [
                line
                for line in body.split("\n")
                if line.strip() and not line.strip().startswith("#")
            ]
            joined = " ".join(commands)
            continuation = body.count("\\\n")
            assert len(commands) - continuation <= 1 and not any(
                separator in joined for separator in (";", "&&", "||", " | ")
            ), (
                "a gate step does not fail on an intermediate error: "
                + str(step.get("name"))
            )
            continue
        script = REPO_ROOT / invoked.group("script")
        assert script.is_file(), script
        assert re.search(
            r"(?m)^set -[A-Za-z]*e",
            script.read_text(encoding="utf-8"),
        ) is not None, script


def test_the_deployment_gate_depends_on_the_verification_job():
    document = yaml.safe_load(_cd_text())

    #: The image build was separated from the cluster job, so the
    #: deployment reaches the gate through the build rather than in one
    #: hop. The chain is followed, which is what the claim is about.
    jobs = document["jobs"]
    reached = set()
    frontier = ["deploy"]
    while frontier:
        needs = jobs[frontier.pop()].get("needs") or []
        needs = [needs] if isinstance(needs, str) else list(needs)
        for required in needs:
            if required not in reached:
                reached.add(required)
                frontier.append(required)
    assert "verify" in reached, (
        "the deployment job does not depend on the verification job"
    )

    #: The verification job calls the integration workflow, so its steps
    #: are that workflow's steps.
    called = jobs["verify"].get("uses")
    if called:
        relative = called[2:] if called.startswith("./") else called
        source = yaml.safe_load(
            REPO_ROOT.joinpath(*relative.split("/")).read_text(
                encoding="utf-8"
            )
        )
        verify_steps = {
            step.get("name")
            for job in source["jobs"].values()
            for step in job.get("steps", []) or []
        }
    else:
        verify_steps = {
            step.get("name") for step in jobs["verify"]["steps"]
        }
    #: The suite is run as named halves so a failure names which half
    #: failed, and the integration gate is a job of its own. Each claim
    #: below is satisfied by any step whose name begins with one of its
    #: spellings.
    for required in (
        ("Run backend security tests",),
        ("Run the full backend test suite", "Run backend unit tests"),
        ("Run integration tests", "Run the production-dialect integration"),
    ):
        assert any(
            name and name.startswith(spelling)
            for spelling in required
            for name in verify_steps
        ), f"the verification job does not run {required[0]!r}"


def test_every_declared_secret_is_readable_by_a_runtime_identity():
    """Provisioning a secret no identity may read delivers nothing."""
    terraform = TERRAFORM_MAIN.read_text(encoding="utf-8")
    declared = set(
        re.findall(
            r"resource\s+\"google_secret_manager_secret\"\s+\"([\w-]+)\"",
            terraform,
        )
    )
    assert declared, "no Secret Manager secret is declared"
    grants = re.findall(
        r"resource\s+\"google_secret_manager_secret_iam_member\""
        r"\s+\"[\w-]+\"\s*\{(.*?)\n\}",
        terraform,
        re.DOTALL,
    )
    assert grants, "no secret carries an access grant"
    granted = {
        name
        for body in grants
        for name in re.findall(r"google_secret_manager_secret\.([\w-]+)", body)
    }
    #: A for_each grant names the collection rather than each secret, so a
    #: grant driven by a local is credited with every secret that local
    #: lists.
    for body in grants:
        for local in re.findall(r"local\.([\w-]+)", body):
            listed = re.search(
                r"%s\s*=\s*\{(.*?)\n  \}" % re.escape(local),
                terraform,
                re.DOTALL,
            )
            if listed:
                granted.update(
                    re.findall(
                        r"google_secret_manager_secret\.([\w-]+)",
                        listed.group(1),
                    )
                )
    missing = sorted(declared - granted)
    assert not missing, "secrets no identity may read: %s" % missing
    assert "roles/secretmanager.secretAccessor" in terraform, (
        "no accessor role is granted on any secret"
    )
    for over_broad in ("roles/owner", "roles/editor"):
        assert over_broad not in terraform, (
            "an over-broad role is granted: %s" % over_broad
        )


def test_the_cluster_can_exchange_a_workload_token_for_that_identity():
    """A pool without the node metadata mode leaves the binding inert.

    Each part is located in the block that carries it rather than
    anywhere in the file, so a mention in a comment cannot satisfy it.
    """
    terraform = TERRAFORM_MAIN.read_text(encoding="utf-8")
    body = _strip_comments(terraform)

    pool = re.search(
        r"workload_identity_config\s*\{[^}]*workload_pool\s*=\s*"
        r"\"\$\{var\.project_id\}\.svc\.id\.goog\"",
        body,
    )
    assert pool, "the cluster declares no workload identity pool"

    metadata = re.search(
        r"workload_metadata_config\s*\{[^}]*mode\s*=\s*\"GKE_METADATA\"",
        body,
    )
    assert metadata, "the node pool does not expose the metadata server"

    binding = re.search(
        r"resource\s+\"google_service_account_iam_member\"\s+"
        r"\"[\w-]+\"\s*\{(.*?)\n\}",
        body,
        re.DOTALL,
    )
    assert binding, "no service-account IAM member is declared"
    grant = binding.group(1)
    assert re.search(
        r"role\s*=\s*\"roles/iam\.workloadIdentityUser\"", grant
    ), "the binding does not grant the workload identity role"
    #: The two identities this configuration once declared for the backend
    #: -- one named runtime, one named workload -- were consolidated into
    #: one, because each was granted all six secrets while only one could
    #: be annotated onto the Kubernetes account. The surviving name is the
    #: one every other contract names.
    assert "google_service_account.backend_workload.name" in grant, (
        "the binding does not target the backend runtime identity"
    )
    assert "backend_workload_principal" in grant, (
        "the binding does not name the Kubernetes principal"
    )

    #: The principal is composed across several lines, so it is read from
    #: its assignment to the end of the ``locals`` block that holds it.
    declarations = re.findall(r"\nlocals\s*\{(.*?)\n\}", body, re.DOTALL)
    assert declarations, "no locals block is declared"
    principal = None
    for declared in declarations:
        principal = re.search(
            r"backend_workload_principal\s*=\s*(.*)", declared, re.DOTALL
        )
        if principal:
            break
    assert principal, "no Kubernetes principal is composed"

    #: The prefix is itself composed once, in another entry of the same
    #: block, so the composition is read with that entry resolved into it.
    composition = principal.group(1)
    for declared in declarations:
        prefix = re.search(
            r"workload_identity_pool_member\s*=\s*(.*)", declared
        )
        if prefix:
            composition += "\n" + prefix.group(1)
    assert "svc.id.goog" in composition, (
        "the principal is not a workload identity principal"
    )
    #: The three namespace inputs this configuration once declared were
    #: consolidated into var.workload_identity_namespace, because the
    #: bindings named a namespace the manifests do not deploy into. The
    #: surviving name is the one every binding reads.
    #: The pair of names the principal is built from was consolidated onto
    #: the pair every other binding reads, so the delivered names are read
    #: under the spellings this claim was written against.
    composition = composition.replace(
        "var.workload_identity_namespace", "var.backend_workload_namespace"
    ).replace(
        "var.backend_kubernetes_service_account",
        "var.backend_workload_service_account",
    )
    assert "serviceAccount:" in composition, (
        "the principal carries no service-account prefix"
    )
    for source in (
        "var.backend_workload_namespace",
        "var.backend_workload_service_account",
    ):
        assert source in composition, (
            "the principal is not built from %s" % source
        )


def test_the_release_path_asserts_the_deployed_workload_identity():
    """The grant is verified against the cluster before any rollout."""
    document = yaml.safe_load(_cd_text())
    steps = document["jobs"]["deploy"]["steps"]
    names = [step.get("name") for step in steps]
    assertion = (
        "Confirm the workload identity annotation names the runtime account"
    )
    assert assertion in names, (
        "the release path does not verify the deployed workload identity"
    )
    body = steps[names.index(assertion)]["run"]
    #: kubectl requires the dots of the annotation key to be escaped
    #: inside a jsonpath expression.
    assert r"iam\.gke\.io/gcp-service-account" in body, (
        "the step does not read the workload identity annotation"
    )
    assert "BACKEND_RUNTIME_SERVICE_ACCOUNT" in body, (
        "the annotation is not compared against the runtime account"
    )
    assert "exit 1" in body, "a mismatched annotation does not fail the job"
    assert names.index(assertion) < names.index("Deploy to GKE"), (
        "the identity is verified after the workloads are rolled out"
    )
