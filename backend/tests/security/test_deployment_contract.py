"""Checks over the definitions that start the service and set it up.

The container stack cannot be built or started from this test process, so
every Compose property below is asserted against the declaration itself.
What is asserted:

* each ``build`` stanza names a context directory that exists and a
  Dockerfile that exists once resolved from that context
* every path the file names resolves inside the repository
* the file carries no placeholder marker and no manual-edit instruction
* the backend service declares every field
  :class:`backend.app.core.config.Settings` publishes, and declares each
  field that has no default with Compose's required-value form
* every declared value is an environment substitution, so no credential
  is carried by the file, and every variable a substitution references is
  documented in ``.env.example``
* the frontend's API target names the port the backend image exposes,
  publishes and listens on, under the variable name the bundle reads
* each frontend build argument either matches an ``ARG`` the frontend
  image declares, and so reaches the built bundle, or is recorded here
  and noted in the Compose file as an argument the build discards
* each health probe invokes an executable its own base image provides

The Settings class is the authority for the environment contract, the
Dockerfiles are the authority for the ports, ``.env.example`` is the
authority for the variable names a developer supplies, and the frontend
source is the authority for the name the bundle reads. A change to any of
them is compared against this file rather than against a second copy of
it.

The stack selects its database with a Compose profile. The ``local``
profile runs the PostgreSQL service declared in the file; the ``gcp``
profile runs the Cloud SQL proxy, which answers to the same ``db``
network alias. Both profiles run ``migrate`` to completion before the
backend starts, so the schema is never behind the code that serves it.

The developer setup script is covered by the last two cases of that
group, which run its bootstrap. They assert that no name it declares
``readonly`` is declared twice, and that its declarations, function
definitions and traps all execute cleanly with its entry point removed.
A shell refuses a second ``readonly`` declaration of one name and
returns non-zero, and the script runs under ``set -Eeuo pipefail``, so
such a declaration ends the run on that line with no step of the setup
having happened -- and ``bash -n`` parses it without complaint, which is
why the bootstrap is executed here rather than only read.

A second group covers the pipeline and infrastructure contract: the two
workflow files, the Terraform module, its variable declarations and the
deployment script. Each property below is asserted against the
declaration, since none of this can be executed from a test process.
What is asserted:

* the deployment workflow is triggered by a completed run of the CI
  workflow, declares no push trigger of its own, and every one of its
  jobs is reached only through that run's success
* the deployment workflow runs none of the verification commands itself,
  so there is no second copy of the gate to drift from the first
* every job that calls ``kubectl`` runs on the self-hosted runner the
  repository variable names, and every GitHub-hosted image the check
  knows about is named in the workflow so that a variable set to one is
  refused before any cluster call
* Terraform and the workflow address the cluster by one location value,
  with the credential flag that accepts the region the module creates
* each image is built with ``-f`` naming its definition under
  ``infrastructure/docker/`` and the context that definition copies from
* the control plane is probed, and the schema migrated, before any
  rollout step changes what is serving, and a migration that did not
  succeed exits non-zero
* the node pool carries an access scope that admits an image pull, and
  the node identity holds a registry-read role
* the control plane keeps no public endpoint, and at least one
  authorized network is required rather than defaulted to none
* the deployment script stops at its first failure, builds from the real
  definitions, addresses the Deployments the workflow addresses,
  migrates before it rolls out, and checks the Cloud Function inputs it
  is given
* no deployment publishes the Cloud Function to unauthenticated callers
* every one of the four runtime pin sites still names the pinned
  interpreter
"""

import fnmatch
import html
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml
from conftest import REPO_ROOT

from backend.app.core.config import (
    LOG_LEVEL_NAMES,
    MAX_SIGNING_KEY_REPEAT_RUN,
    MIN_SIGNING_KEY_BYTES,
    MIN_SIGNING_KEY_DISTINCT_CHARS,
    Settings,
)
from backend.app.main import READINESS_PATH

#: Compose file under test.
COMPOSE_PATH = REPO_ROOT / "infrastructure" / "docker" / "docker-compose.yml"

#: Backend image definition, the authority for the backend port.
BACKEND_DOCKERFILE = (
    REPO_ROOT / "infrastructure" / "docker" / "Dockerfile.backend"
)

#: Frontend image definition, the authority for the frontend port.
FRONTEND_DOCKERFILE = (
    REPO_ROOT / "infrastructure" / "docker" / "Dockerfile.frontend"
)

#: Environment file documenting every variable a developer supplies.
ENVIRONMENT_EXAMPLE = REPO_ROOT / ".env.example"

#: Frontend module that reads the API address out of the bundle.
FRONTEND_API_MODULE = (
    REPO_ROOT / "frontend" / "src" / "services" / "api.ts"
)

#: Script that prepares a local development environment.
SETUP_SCRIPT = REPO_ROOT / "scripts" / "setup_dev_environment.sh"

#: Services the file is required to declare, in order.
EXPECTED_SERVICES = (
    "frontend",
    "backend",
    "migrate",
    "cache",
    "db",
    "cloud-sql-proxy",
)

#: Services that build an image from a context in this repository.
BUILD_SERVICES = ("frontend", "backend", "migrate")

#: Services that carry the backend environment anchor.
ANCHORED_SERVICES = ("backend", "migrate")

#: Service the published settings are read from.
BACKEND_SERVICE = "backend"

#: Setting naming the threshold every structured record is filtered at.
LOG_LEVEL_SETTING = "LOG_LEVEL"

#: Settings that were once declared, published and documented but that
#: nothing in the application ever read. Each is asserted absent from
#: every one of those places, so a deployment is never told it can
#: influence behaviour it cannot.
RETIRED_SETTINGS = ("SENTRY_DSN",)

#: Profiles each service is selected by. ``db`` runs only for the local
#: profile and the proxy only for the gcp one, so exactly one of them
#: answers to the ``db`` name in any single stack. ``cache`` runs for both,
#: because the application refuses an in-process rate-limit store under any
#: environment other than local and so needs one to address.
EXPECTED_PROFILES = {
    "frontend": ["local", "gcp"],
    "backend": ["local", "gcp"],
    "migrate": ["local", "gcp"],
    "cache": ["local", "gcp"],
    "db": ["local"],
    "cloud-sql-proxy": ["gcp"],
}

#: Service holding the shared rate-limit counters.
CACHE_SERVICE = "cache"

#: Address that reaches :data:`CACHE_SERVICE` from the backend container,
#: as documented in ``.env.example``.
CACHE_STORAGE_URI = "redis://cache:6379/0"

#: Rate-limit storage schemes the application keeps inside one process. A
#: deployed stack may name none of them, which is what makes the service
#: above a requirement rather than a convenience.
IN_PROCESS_STORAGE_SCHEMES = (
    "bounded-memory://",
    "memory://",
    "async+memory://",
)

#: Service running the Cloud SQL proxy under the gcp profile.
PROXY_SERVICE = "cloud-sql-proxy"

#: Variable naming the instance the proxy connects to.
PROXY_INSTANCE_VARIABLE = "CLOUD_SQL_INSTANCE_CONNECTION_NAME"

#: Repository the proxy image is pulled from. The host keeps the gcr.io
#: name for historical reasons and is served from Artifact Registry.
PROXY_IMAGE_REPOSITORY = "gcr.io/cloud-sql-connectors/cloud-sql-proxy"

#: Settings the Compose document demands even though the settings class
#: defaults them. Each entry selects behaviour that the class's own
#: default would relax, so a Compose default would let a deployed profile
#: inherit the relaxation without naming it.
DEMANDED_DESPITE_A_CLASS_DEFAULT = ("ENVIRONMENT",)

#: Project name the stack declares. It prefixes every container, the
#: network and the db-data volume the stack creates.
EXPECTED_PROJECT_NAME = "apartment-finder"

#: Top-level key Compose no longer reads and warns about on every
#: invocation while it is present.
OBSOLETE_TOP_LEVEL_KEY = "version"

#: Text fragments that mark a value a human is expected to edit in place.
FORBIDDEN_MARKERS = (
    "HUMAN ASSISTANCE NEEDED",
    "<INSTANCE_CONNECTION_NAME>",
    "CHANGE_ME",
    "REPLACE_",
)

#: Shape of a value a human is expected to edit in place: a bare
#: ``<...>`` token outside a substitution.
PLACEHOLDER_TOKEN = re.compile(r"<[A-Z][A-Z0-9_]*>")

#: Shape of one declared value: a substitution carrying either a
#: required-value message or a default.
SUBSTITUTION = re.compile(
    r"^\$\{(?P<referenced>[A-Z][A-Z0-9_]*)"
    r"(?P<operator>:\?|:-)(?P<argument>.*)\}$"
)

#: Settings whose value is read from a differently named variable, and
#: the variable each reads.
#:
#: A developer's own shell almost always carries ``DATABASE_URL`` and
#: ``ENVIRONMENT`` for the host checkout, where the database answers on
#: ``localhost``. Injecting those straight into a container would point
#: it at itself, so the stack reads compose-side names instead and
#: ``scripts/setup_dev_environment.sh`` writes them. Every name below is
#: documented in ``.env.example``, which the tests here assert.
DOCUMENTED_ALIASES = {
    "ENVIRONMENT": "BACKEND_ENVIRONMENT",
    "DATABASE_URL": "COMPOSE_DATABASE_URL",
    "ALLOWED_ORIGINS": "BACKEND_ALLOWED_ORIGINS",
    "ALLOWED_HOSTS": "BACKEND_ALLOWED_HOSTS",
}

#: Operator that stops the stack when the value is absent.
REQUIRED_OPERATOR = ":?"

#: Operator that supplies a default when the value is absent.
DEFAULT_OPERATOR = ":-"

#: Probe forms Compose accepts. The shell form is required whenever the
#: command interpolates a variable of its own.
PROBE_FORMS = ("CMD", "CMD-SHELL")

#: Executable each service's probe is required to invoke. Each one is
#: provided by that service's own base image.
EXPECTED_PROBE_EXECUTABLE = {
    "frontend": "wget",
    "backend": "python",
    "cache": "redis-cli",
    "db": "pg_isready",
}

#: Executable no probe may invoke: neither ``python:3.9-slim`` nor
#: ``nginx:alpine`` installs it.
FORBIDDEN_PROBE_EXECUTABLE = "curl"

#: Build argument the frontend carries the backend's address in.
FRONTEND_TARGET_NAME = "REACT_APP_API_BASE_URL"

#: Frontend build arguments the frontend image declares no ``ARG`` for.
#: The build discards each of them, so the built bundle carries no value
#: for any name listed here. The record is empty: the frontend image
#: declares an ``ARG`` for every argument the Compose file supplies it,
#: and exports each one before the build command runs.
DISCARDED_FRONTEND_ARGUMENTS = ()

#: Wording the Compose file carries while it supplies an argument the
#: build discards. It is matched literally and on one line, so a comment
#: rewrapped across it fails the case that reads it.
DISCARDED_ARGUMENT_NOTE = "the build discards"

#: Shape of one ``ARG`` declaration in an image definition.
IMAGE_ARGUMENT = re.compile(
    r"^ARG\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)

#: Shape of one ``readonly`` declaration in a shell script.
READONLY_DECLARATION = re.compile(
    r"^\s*readonly\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE
)

#: The setup script's entry point: the single line that runs it.
SETUP_ENTRY_POINT = re.compile(r'^main\s+"\$@"\s*$', re.MULTILINE)

#: Seconds the bootstrap shell is allowed before it is abandoned.
BOOTSTRAP_TIMEOUT_SECONDS = 120.0

#: Function of the setup script the generated-secret cases drive.
ENV_FUNCTION = "configure_env_vars"

#: Entries the setup script replaces as it writes the template through.
GENERATED_KEY_ENTRY = "SECRET_KEY"

GENERATED_PASSWORD_ENTRY = "ADMIN_SEED_PASSWORD"

#: Least number of characters the generated administrator password must
#: carry. The setup script and the registration policy both require this.
MIN_ADMIN_PASSWORD_LENGTH = 12

#: Shell override that makes ``command -v openssl`` report absent, so the
#: interpreter branch of the key generator runs. Both branches of the
#: generator are covered by parametrising over this.
FORCE_INTERPRETER_BRANCH = (
    "command() {\n"
    '    if [ "${2-}" = "openssl" ]; then\n'
    "        return 1\n"
    "    fi\n"
    '    builtin command "$@"\n'
    "}\n"
)

#: The generation branches driven, and the shell prelude each needs.
KEY_GENERATION_BRANCHES = ("openssl", "interpreter")

#: Identifier the backend image's unprivileged account must carry. The
#: numeric value matters as well as the name: a cluster policy that
#: refuses ``runAsUser: 0`` compares the number.
CONTAINER_USER_NAME = "appuser"

CONTAINER_GROUP_NAME = "appgroup"

CONTAINER_USER_ID = 1001

CONTAINER_GROUP_ID = 1001

#: Directory the image serves from, which must be left unwritable.
CONTAINER_APPLICATION_DIRECTORY = "/app"

#: Shape of one ``USER`` instruction.
USER_INSTRUCTION = re.compile(
    r"^\s*USER\s+(\S+)\s*$", re.MULTILINE | re.IGNORECASE
)

#: Shape of one ``COPY`` instruction's source and destination.
COPY_INSTRUCTION = re.compile(
    r"^\s*COPY\s+(?!--)(.+?)\s*$", re.MULTILINE | re.IGNORECASE
)

#: Build contexts the backend image is built from, paired with the ignore
#: file that governs each. Compose and the deployment script build from
#: the backend directory; a root-context build is governed by the root
#: file, which carries the same pattern set.
BACKEND_BUILD_CONTEXTS = (
    ("backend", REPO_ROOT / "backend" / ".dockerignore"),
    ("root", REPO_ROOT / ".dockerignore"),
)

#: Paths that must never enter a build context. Each is a path relative to
#: the context root, in the form Docker matches ignore patterns against.
EXCLUDED_CONTEXT_PATHS = (
    ".env",
    ".env.local",
    ".env.production",
    "secrets/service-account.json",
    "secrets/key.json",
    "google-credentials.json",
    "gcp-service-account.json",
    "credentials.json",
    "app/credentials.json",
    "id_rsa",
    "server.pem",
    "server.key",
    "cluster.kubeconfig",
    ".netrc",
    "app/.env",
    "nested/deeper/.env",
)

#: Paths the image needs, which no exclusion may match. Asserting these
#: keeps the exclusion list from being widened into a broken build.
REQUIRED_CONTEXT_PATHS = (
    "requirements.txt",
    "app/main.py",
    "app/core/security.py",
    "alembic.ini",
    "migrations/env.py",
)

#: Prefix every name the frontend bundle inlines at build time carries.
FRONTEND_VARIABLE_PREFIX = "REACT_APP_"

#: Command each image definition builds its artifact with. An ``ARG``
#: declared after it cannot reach it.
BUILD_COMMAND = "npm run build"

#: Frontend modules that read a build-time value out of the bundle. The
#: frontend source is read-only here and is the authority for the names.
FRONTEND_CONFIGURED_MODULES = (
    REPO_ROOT / "frontend" / "src" / "services" / "api.ts",
    REPO_ROOT / "frontend" / "src" / "services" / "paypal.ts",
    REPO_ROOT / "frontend" / "src" / "index.tsx",
)


def _compose_document():
    """Returns the parsed Compose document."""
    return yaml.safe_load(COMPOSE_PATH.read_text(encoding="utf-8"))


def _compose_text():
    """Returns the Compose file as text."""
    return COMPOSE_PATH.read_text(encoding="utf-8")


def _service(name):
    """Returns one service definition."""
    return _compose_document()["services"][name]


def _environment_entries(name):
    """Returns one service's declared environment as name/value pairs.

    Compose accepts a mapping and a ``NAME=value`` list. The stack uses
    the mapping so the backend and the migration job can share one
    anchor, and both forms are read here so the assertions hold whichever
    the file uses.
    """
    declared = _service(name).get("environment") or {}
    if isinstance(declared, dict):
        return [(key, str(value)) for key, value in declared.items()]
    pairs = []
    for entry in declared:
        key, _, value = str(entry).partition("=")
        pairs.append((key, value))
    return pairs


def _build_arguments(name):
    """Returns one service's build arguments as name/value pairs."""
    declared = (_service(name).get("build") or {}).get("args") or {}
    if isinstance(declared, dict):
        return [(key, str(value)) for key, value in declared.items()]
    pairs = []
    for entry in declared:
        key, _, value = str(entry).partition("=")
        pairs.append((key, value))
    return pairs


def _declared_names(name):
    """Returns the setting names one service declares."""
    return set(key for key, _ in _environment_entries(name))


def _services_declaring_an_environment():
    """Returns the names of services that declare any environment."""
    document = _compose_document()
    return tuple(
        name
        for name, service in document["services"].items()
        if service.get("environment")
    )


def _services_declaring_a_probe():
    """Returns the names of services that declare a health probe."""
    document = _compose_document()
    return tuple(
        name
        for name, service in document["services"].items()
        if service.get("healthcheck")
    )


def _documented_variables():
    """Returns the variable names ``.env.example`` documents."""
    return set(
        match.group(1)
        for match in re.finditer(
            r"^([A-Z][A-Z0-9_]*)=",
            ENVIRONMENT_EXAMPLE.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )


def _documented_values():
    """Returns the value ``.env.example`` ships for each variable."""
    return dict(
        (match.group(1), match.group(2))
        for match in re.finditer(
            r"^([A-Z][A-Z0-9_]*)=(.*)$",
            ENVIRONMENT_EXAMPLE.read_text(encoding="utf-8"),
            re.MULTILINE,
        )
    )


def _compose_required_variables():
    """Returns the variables the Compose file marks required."""
    return set(
        match.group(1)
        for match in re.finditer(
            r"\$\{([A-Z][A-Z0-9_]*)" + re.escape(REQUIRED_OPERATOR),
            _compose_text(),
        )
    )


def _settings_fields():
    """Returns the published settings fields, keyed by name."""
    return dict(Settings.__fields__)


def _required_settings():
    """Returns the settings that have no default."""
    return set(
        name
        for name, field in _settings_fields().items()
        if field.required
    )


def _exposed_port(dockerfile):
    """Returns the single port an image definition exposes."""
    ports = re.findall(
        r"^EXPOSE\s+(\d+)",
        dockerfile.read_text(encoding="utf-8"),
        re.MULTILINE,
    )
    assert len(ports) == 1, dockerfile.name
    return int(ports[0])


def _declared_image_arguments(dockerfile):
    """Returns the ``ARG`` names one image definition declares."""
    return set(
        IMAGE_ARGUMENT.findall(dockerfile.read_text(encoding="utf-8"))
    )


def _setup_script_text():
    """Returns the developer setup script as text."""
    return SETUP_SCRIPT.read_text(encoding="utf-8")


def _setup_script_bootstrap():
    """Returns the setup script with its entry point removed.

    What is left declares every constant, defines every function and
    installs both traps, and runs no step of the setup. Line endings are
    normalised, so the text handed to a shell is the text the repository
    carries however the checkout translated it.
    """
    text = _setup_script_text().replace("\r\n", "\n")
    bootstrap, removed = SETUP_ENTRY_POINT.subn("", text)

    assert removed == 1, removed
    return bootstrap


def _template_entry(name):
    """Returns the value ``.env.example`` ships for ``name``."""
    prefix = name + "="
    for line in ENVIRONMENT_EXAMPLE.read_text(
        encoding="utf-8"
    ).splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    raise AssertionError("%s is absent from the template" % name)


def _written_entry(path, name):
    """Returns the value the written environment file carries."""
    prefix = name + "="
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    raise AssertionError("%s is absent from %s" % (name, path))


def _run_env_configuration(branch):
    """Runs the setup script's environment step in an isolated root.

    The bootstrap is taken first, so no step of the setup runs by itself,
    and then ``REPO_ROOT`` is pointed at a temporary directory holding a
    copy of the template and :data:`ENV_FUNCTION` alone is called. Nothing
    is installed, no database is touched and the repository's own
    environment file is never read or written.

    Returns the completed process and the text of the file the step wrote,
    or skips when no shell -- or, for the ``openssl`` branch, no
    ``openssl`` -- is available to run it.
    """
    shell = shutil.which("bash")
    if shell is None:
        pytest.skip("no POSIX shell is available to run the setup step")

    prelude = ""
    if branch == "openssl":
        openssl = shutil.which("openssl")
        if openssl is None:
            pytest.skip("openssl is not available on this host")
        environment = None
    else:
        prelude = FORCE_INTERPRETER_BRANCH
        environment = None

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory) / "repo"
        root.mkdir()
        shutil.copyfile(ENVIRONMENT_EXAMPLE, root / ENVIRONMENT_EXAMPLE.name)
        program = "".join(
            [
                _setup_script_bootstrap(),
                "\n",
                prelude,
                'REPO_ROOT="%s"\n' % root.as_posix(),
                'VENV_PYTHON="%s"\n' % _interpreter_posix_path(),
                "%s\n" % ENV_FUNCTION,
            ]
        )
        driver = Path(directory) / SETUP_SCRIPT.name
        driver.write_bytes(program.encode("utf-8"))
        try:
            completed = subprocess.run(
                [shell, str(driver)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=BOOTSTRAP_TIMEOUT_SECONDS,
                env=environment,
            )
        except subprocess.TimeoutExpired as expired:
            raise AssertionError(
                "the {0} step did not finish within {1} seconds; "
                "stdout={2!r} stderr={3!r}".format(
                    ENV_FUNCTION,
                    BOOTSTRAP_TIMEOUT_SECONDS,
                    expired.stdout,
                    expired.stderr,
                )
            ) from None

        assert completed.returncode == 0, completed.stderr.decode(
            "utf-8", "replace"
        )
        written = root / ".env"
        assert written.is_file(), completed.stdout.decode(
            "utf-8", "replace"
        )
        return completed, written.read_text(encoding="utf-8")


def _interpreter_posix_path():
    """Returns this interpreter as a path a POSIX shell can execute."""
    import sys

    return Path(sys.executable).as_posix()


def _generated_key(branch):
    """Returns the signing key one isolated run wrote."""
    _, text = _run_env_configuration(branch)
    prefix = GENERATED_KEY_ENTRY + "="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    raise AssertionError(
        "%s is absent from the written file" % GENERATED_KEY_ENTRY
    )


@pytest.mark.parametrize("branch", KEY_GENERATION_BRANCHES)
def test_the_setup_step_writes_a_strong_generated_signing_key(branch):
    """The generated key clears the rules the settings validator applies.

    The step is executed rather than read, in an isolated root, so the
    value asserted is the one a developer's environment file would carry.
    The thresholds come from the configuration module, which is the
    authority for them, rather than being restated here.
    """
    key = _generated_key(branch)

    assert len(key.encode("utf-8")) >= MIN_SIGNING_KEY_BYTES
    assert len(set(key)) >= MIN_SIGNING_KEY_DISTINCT_CHARS
    assert _longest_repeat(key) <= MAX_SIGNING_KEY_REPEAT_RUN


@pytest.mark.parametrize("branch", KEY_GENERATION_BRANCHES)
def test_the_generated_signing_key_is_not_the_shipped_placeholder(branch):
    """The template's placeholder never survives into the written file."""
    key = _generated_key(branch)
    placeholder = _template_entry(GENERATED_KEY_ENTRY)

    assert placeholder
    assert key != placeholder
    assert "CHANGE_ME" not in key
    assert "your_secret_key_here" not in key
    assert "placeholder" not in key.lower()


def test_two_runs_generate_different_signing_keys():
    """A key is generated per run, so two environments never share one."""
    first = _generated_key(KEY_GENERATION_BRANCHES[0])
    second = _generated_key(KEY_GENERATION_BRANCHES[0])

    assert first != second


def test_the_written_file_carries_the_generated_administrator_password():
    """The seed password is generated too, and reaches the file alone."""
    _, text = _run_env_configuration(KEY_GENERATION_BRANCHES[0])
    prefix = GENERATED_PASSWORD_ENTRY + "="
    values = [
        line[len(prefix):]
        for line in text.splitlines()
        if line.startswith(prefix)
    ]

    assert len(values) == 1
    password = values[0]
    assert len(password) >= MIN_ADMIN_PASSWORD_LENGTH
    assert password != _template_entry(GENERATED_PASSWORD_ENTRY)
    assert "CHANGE_ME" not in password


def test_the_written_file_keeps_every_other_template_entry():
    """Only the two generated entries differ from the template.

    The step writes the template through line by line, so a change that
    dropped or rewrote an unrelated entry -- and so left a developer
    without a documented setting -- fails here.
    """
    _, text = _run_env_configuration(KEY_GENERATION_BRANCHES[0])
    generated = (GENERATED_KEY_ENTRY + "=", GENERATED_PASSWORD_ENTRY + "=")
    template = [
        line
        for line in ENVIRONMENT_EXAMPLE.read_text(
            encoding="utf-8"
        ).splitlines()
        if not line.startswith(generated)
    ]
    written = [
        line
        for line in text.splitlines()
        if not line.startswith(generated)
    ]

    assert written == template


def _longest_repeat(value):
    """Returns the length of the longest run of one repeated character."""
    longest = 0
    run = 0
    previous = None
    for character in value:
        run = run + 1 if character == previous else 1
        previous = character
        longest = max(longest, run)
    return longest


# ---------------------------------------------------------------------
# The backend image's container contract
# ---------------------------------------------------------------------


def _backend_dockerfile_text():
    """Returns the backend image definition as text."""
    return BACKEND_DOCKERFILE.read_text(encoding="utf-8")


def _segments_match(pattern_parts, path_parts):
    """Reports whether one ignore pattern matches one path.

    Matching follows the build context's rules rather than the shell's: a
    pattern is compared segment by segment, ``**`` spans any number of
    segments including none, and a wildcard inside a segment never
    crosses a separator.
    """
    if not pattern_parts:
        return not path_parts
    head = pattern_parts[0]
    if head == "**":
        rest = pattern_parts[1:]
        if not rest:
            return True
        for index in range(len(path_parts) + 1):
            if _segments_match(rest, path_parts[index:]):
                return True
        return False
    if not path_parts:
        return False
    if not fnmatch.fnmatchcase(path_parts[0], head):
        return False
    return _segments_match(pattern_parts[1:], path_parts[1:])


def _ignore_patterns(path):
    """Returns the effective patterns one ignore file declares."""
    patterns = []
    for line in path.read_text(encoding="utf-8").splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        patterns.append(entry)
    return patterns


def _is_excluded(patterns, candidate):
    """Reports whether the patterns exclude ``candidate`` or a parent.

    A pattern naming a directory excludes everything beneath it, so each
    ancestor of the candidate is tested as well as the candidate itself.
    """
    parts = candidate.split("/")
    for pattern in patterns:
        directory_only = pattern.endswith("/")
        pattern_parts = [
            part for part in pattern.strip("/").split("/") if part
        ]
        for depth in range(1, len(parts) + 1):
            prefix = parts[:depth]
            if depth < len(parts) or directory_only:
                # A directory pattern, or a pattern matching an ancestor,
                # removes the whole subtree.
                if _segments_match(pattern_parts, prefix):
                    return True
            if depth == len(parts) and not directory_only:
                if _segments_match(pattern_parts, prefix):
                    return True
    return False


def test_the_backend_image_creates_an_unprivileged_group_and_user():
    """The account is a system account carrying the fixed identifiers."""
    text = _backend_dockerfile_text()

    assert "--system --gid %d %s" % (
        CONTAINER_GROUP_ID,
        CONTAINER_GROUP_NAME,
    ) in text
    assert "--uid %d" % CONTAINER_USER_ID in text
    assert "--gid %s" % CONTAINER_GROUP_NAME in text
    assert CONTAINER_USER_NAME in text
    assert "--no-create-home" in text
    assert "nologin" in text


def test_the_backend_image_ends_as_the_unprivileged_user():
    """The last USER instruction is the unprivileged one, never root.

    An image that creates the account and then returns to root gains
    nothing, so the final instruction is what is asserted rather than the
    presence of one anywhere.
    """
    declared = USER_INSTRUCTION.findall(_backend_dockerfile_text())

    assert declared
    assert declared[-1] == CONTAINER_USER_NAME
    assert "root" not in declared
    assert "0" not in declared


def test_the_backend_image_leaves_the_application_tree_unwritable():
    """Ownership stays with root and write permission is removed."""
    text = _backend_dockerfile_text()

    assert (
        "chown -R root:root %s" % CONTAINER_APPLICATION_DIRECTORY in text
    )
    assert "chmod -R a-w,a+rX %s" % CONTAINER_APPLICATION_DIRECTORY in text


def test_the_ownership_change_precedes_the_user_switch():
    """Permissions are set while the build can still set them."""
    text = _backend_dockerfile_text()
    hardening = text.index("chmod -R a-w,a+rX")
    switch = text.index("USER %s" % CONTAINER_USER_NAME)

    assert hardening < switch


def test_the_backend_image_copies_no_path_outside_its_context():
    """Every COPY source is relative, so nothing escapes the context."""
    for source in COPY_INSTRUCTION.findall(_backend_dockerfile_text()):
        first = source.split()[0]
        assert not first.startswith("/")
        assert ".." not in first


@pytest.mark.parametrize("label,ignore_file", BACKEND_BUILD_CONTEXTS)
@pytest.mark.parametrize("candidate", EXCLUDED_CONTEXT_PATHS)
def test_no_secret_path_enters_the_build_context(
    label, ignore_file, candidate
):
    """The ignore file that governs each context excludes each path.

    The definition copies its whole context, so an ignore file is the only
    thing standing between a developer's environment file or key material
    and a published image. Both contexts the backend image is built from
    are covered, since a pattern set that protects one and not the other
    protects nothing in practice.
    """
    assert ignore_file.is_file(), label
    patterns = _ignore_patterns(ignore_file)

    assert _is_excluded(patterns, candidate), (label, candidate)


@pytest.mark.parametrize("label,ignore_file", BACKEND_BUILD_CONTEXTS)
@pytest.mark.parametrize("candidate", REQUIRED_CONTEXT_PATHS)
def test_the_exclusions_keep_the_application_in_the_context(
    label, ignore_file, candidate
):
    """No exclusion removes a path the image needs to run."""
    patterns = _ignore_patterns(ignore_file)

    assert not _is_excluded(patterns, candidate), (label, candidate)


def test_the_compose_file_parses_and_declares_every_service():
    """Asserts the file is one mapping carrying every service."""
    document = _compose_document()

    assert isinstance(document, dict)
    assert tuple(document["services"]) == EXPECTED_SERVICES


@pytest.mark.parametrize("service", EXPECTED_SERVICES)
def test_each_service_declares_the_profiles_that_select_it(service):
    """Asserts one profile selects the database each stack runs.

    The local stack runs the PostgreSQL service and the gcp stack runs
    the proxy, so a single stack never starts both under the ``db`` name.
    """
    assert _service(service)["profiles"] == EXPECTED_PROFILES[service]


def test_exactly_one_database_service_answers_to_each_profile():
    """Asserts no profile selects two databases and none selects zero."""
    for profile in ("local", "gcp"):
        answering = [
            name
            for name in ("db", PROXY_SERVICE)
            if profile in EXPECTED_PROFILES[name]
        ]
        assert len(answering) == 1, profile


@pytest.mark.parametrize("service", BUILD_SERVICES)
def test_each_build_stanza_resolves_to_files_that_exist(service):
    """Asserts the context directory and the Dockerfile both exist.

    The Dockerfile is resolved from the context, which is how Compose
    resolves it, and both paths are asserted to stay inside the
    repository.
    """
    build = _service(service)["build"]
    context = (COMPOSE_PATH.parent / build["context"]).resolve()
    dockerfile = (context / build["dockerfile"]).resolve()

    assert context.is_dir(), build["context"]
    assert dockerfile.is_file(), build["dockerfile"]
    assert REPO_ROOT.resolve() in context.parents or (
        context == REPO_ROOT.resolve()
    )
    assert REPO_ROOT.resolve() in dockerfile.parents


def test_the_backend_build_context_carries_the_paths_its_image_copies():
    """Asserts the backend context holds what its Dockerfile copies.

    ``Dockerfile.backend`` copies ``requirements.txt`` from the context
    root and then copies the context into ``/app/backend``, so the
    context is required to be the backend directory itself.
    """
    build = _service("backend")["build"]
    context = (COMPOSE_PATH.parent / build["context"]).resolve()

    assert (context / "requirements.txt").is_file()
    assert (context / "app" / "main.py").is_file()


def test_the_frontend_build_context_carries_the_paths_its_image_copies():
    """Asserts the frontend context holds what its Dockerfile copies."""
    build = _service("frontend")["build"]
    context = (COMPOSE_PATH.parent / build["context"]).resolve()

    assert (context / "package.json").is_file()
    assert (context / "package-lock.json").is_file()


def test_the_migration_job_builds_the_image_the_backend_runs():
    """Asserts one image carries the application and its revisions.

    The migration job applies the Alembic revisions the backend's own
    code expects, so it is required to build from the same context and
    Dockerfile rather than from an image of its own.
    """
    backend = _service("backend")["build"]
    migrate = _service("migrate")["build"]

    assert migrate["context"] == backend["context"]
    assert migrate["dockerfile"] == backend["dockerfile"]


def test_the_backend_starts_only_after_the_migration_job_succeeds():
    """Asserts the schema is never behind the code that serves it."""
    depends = _service("backend")["depends_on"]

    assert depends["migrate"]["condition"] == "service_completed_successfully"


def test_the_stack_provides_a_store_the_rate_limiter_can_share():
    """Asserts a shared rate-limit store is declared and addressable.

    The application refuses an in-process store under any environment
    other than local, so a stack that declares no store cannot be started
    outside a local run at all. The service is declared on every profile
    and its address is documented, so the setting has somewhere to point.
    """
    cache = _service(CACHE_SERVICE)

    assert cache["profiles"] == EXPECTED_PROFILES[CACHE_SERVICE]
    assert cache["image"].startswith("redis:")
    assert CACHE_STORAGE_URI in _documented_values().values() or (
        CACHE_STORAGE_URI
        in ENVIRONMENT_EXAMPLE.read_text(encoding="utf-8")
    )


def test_the_shared_store_publishes_no_port_and_persists_nothing():
    """Asserts the store is reachable only from the stack's own network.

    The counters are rebuilt by the traffic that follows a restart, so
    nothing is written to disk, and the store is bounded by an eviction
    policy rather than growing until writes are refused.
    """
    cache = _service(CACHE_SERVICE)
    command = " ".join(str(item) for item in cache["command"])

    assert "ports" not in cache
    assert "volumes" not in cache
    assert "--appendonly no" in command
    assert "--maxmemory-policy allkeys-lru" in command
    assert "--maxmemory" in command


def test_the_backend_waits_for_the_store_it_shares_counters_through():
    """Asserts the backend starts only once the store answers."""
    depends = _service("backend")["depends_on"]

    assert depends[CACHE_SERVICE]["condition"] == "service_healthy"


def test_the_documented_storage_address_names_the_declared_service():
    """Asserts the documented address resolves inside the stack.

    Compose resolves a service name on the stack network, so the host of
    the documented URI is required to be the name of a declared service
    rather than a host only the developer's own machine can reach.
    """
    host = CACHE_STORAGE_URI.split("://", 1)[1].split(":", 1)[0]

    assert host in _compose_document()["services"]
    assert host == CACHE_SERVICE


def test_the_documented_default_store_is_accepted_only_locally():
    """Asserts the shipped default is one the local environment accepts.

    The example file ships an in-process default, which the application
    accepts only while ENVIRONMENT is local. The compose default for the
    environment is asserted to be that same value, so the shipped pair
    starts, and the shared address is documented beside it for any other
    environment.
    """
    documented = _documented_values()
    shipped = documented["RATE_LIMIT_STORAGE_URI"]
    environment = dict(_environment_entries("backend"))
    match = SUBSTITUTION.match(environment["ENVIRONMENT"])

    assert shipped in IN_PROCESS_STORAGE_SCHEMES, shipped
    assert match is not None
    # The environment is required rather than defaulted, so that no stack
    # ever starts without stating which posture it is running under. What
    # the shipped pair resolves to is then the template's own value for the
    # variable the substitution references, and that is what has to be
    # local for the shipped store to be accepted.
    if match.group("operator") == ":-":
        resolved = match.group("argument")
    else:
        resolved = documented[match.group("referenced")]
    assert resolved == "local", resolved


def test_the_compose_file_carries_no_placeholder_to_edit_by_hand():
    """Asserts no marker and no bare ``<TOKEN>`` remains in the file."""
    text = _compose_text()

    for marker in FORBIDDEN_MARKERS:
        assert marker not in text, marker
    assert PLACEHOLDER_TOKEN.search(text) is None


def test_every_declared_value_is_an_environment_substitution():
    """Asserts no service carries a literal value for any setting.

    Each entry is required to reference a variable of its own name, or
    the compose-side name recorded in :data:`DOCUMENTED_ALIASES`, so the
    file carries no credential and no endpoint of its own.
    """
    for service in _services_declaring_an_environment():
        for name, value in _environment_entries(service):
            match = SUBSTITUTION.match(value)
            assert match is not None, (service, name, value)
            expected = DOCUMENTED_ALIASES.get(name, name)
            assert match.group("referenced") == expected, (service, name)


def test_every_build_argument_is_an_environment_substitution():
    """Asserts no build argument carries a literal value either.

    A build argument is baked into the image, so a credential placed
    here would outlive the container that read it.
    """
    for service in BUILD_SERVICES:
        for name, value in _build_arguments(service):
            match = SUBSTITUTION.match(value)
            assert match is not None, (service, name, value)


def test_every_referenced_variable_is_documented():
    """Asserts ``.env.example`` names every variable the file reads.

    This is what licenses the compose-side names: a developer can only
    supply a value whose name is written down, so a substitution the
    example file does not document is unreachable in practice.
    """
    documented = _documented_variables()
    assert documented, ".env.example documents at least one variable"

    for service in _compose_document()["services"]:
        declared = _environment_entries(service) + _build_arguments(service)
        for name, value in declared:
            match = SUBSTITUTION.match(value)
            if match is None:
                continue
            referenced = match.group("referenced")
            assert referenced in documented, (service, name, referenced)


def test_every_recorded_alias_is_used_and_documented():
    """Asserts the alias record matches the file and the example.

    An alias left in the record after the file stopped using it would
    quietly widen what the substitution assertion above accepts, so each
    one is asserted to still be in force here.
    """
    documented = _documented_variables()
    declared = dict(_environment_entries("backend"))

    for name, referenced in DOCUMENTED_ALIASES.items():
        assert name in declared, name
        assert referenced in declared[name], name
        assert referenced in documented, referenced
        assert referenced != name, name


def test_the_backend_declares_every_published_setting():
    """Asserts the declared names are exactly the settings fields."""
    declared = _declared_names("backend")

    assert declared == set(_settings_fields())


@pytest.mark.parametrize("service", ANCHORED_SERVICES)
def test_every_anchored_service_declares_the_same_environment(service):
    """Asserts the migration job reads the settings the backend reads.

    The revisions resolve the database and the seeded administrator from
    the same settings the application does, so a job started with a
    narrower environment would fail or seed the wrong account.
    """
    assert _environment_entries(service) == _environment_entries("backend")


def test_every_setting_without_a_default_is_declared_as_required():
    """Asserts a setting with no default stops the stack when absent.

    A setting the class defaults is asserted to carry a default here
    instead, so an absent optional value never blocks a start. The one
    exception is listed in :data:`DEMANDED_DESPITE_A_CLASS_DEFAULT`.
    """
    required = _required_settings() | set(DEMANDED_DESPITE_A_CLASS_DEFAULT)
    assert required, "the settings class publishes a required field"

    for name, value in _environment_entries("backend"):
        match = SUBSTITUTION.match(value)
        operator = match.group("operator")
        if name in required:
            assert operator == REQUIRED_OPERATOR, (name, value)
            assert match.group("argument").strip(), (name, value)
        else:
            assert operator == DEFAULT_OPERATOR, (name, value)


@pytest.mark.parametrize("name", DEMANDED_DESPITE_A_CLASS_DEFAULT)
def test_the_environment_name_is_demanded_despite_its_class_default(name):
    """Asserts the posture selector carries no Compose default.

    ``ENVIRONMENT`` defaults in the settings class, so a process started
    by hand runs locally. Compose demands it instead: every non-local
    guard the class applies is selected by this one value, so a Compose
    default of ``local`` would let the Cloud SQL profile inherit the whole
    local posture -- secrets read from a file, rate limits counted in one
    process, plaintext callbacks -- without naming any of it.
    """
    assert not _settings_fields()[name].required, name

    declared = dict(_environment_entries("backend"))[name]
    match = SUBSTITUTION.match(declared)

    assert match.group("operator") == REQUIRED_OPERATOR, declared
    assert match.group("argument").strip(), declared


def test_the_database_password_is_required_rather_than_defaulted():
    """Asserts the local database is never started on a known password."""
    declared = dict(_environment_entries("db"))
    value = declared["POSTGRES_PASSWORD"]

    assert SUBSTITUTION.match(value).group("operator") == REQUIRED_OPERATOR


def test_the_proxy_target_is_demanded_rather_than_defaulted():
    """Asserts the proxy is never started against an implied instance.

    The instance name is demanded, so no invocation can inherit a value
    that looks configured: Compose stops and names the variable when it is
    absent or empty. The proxy is declared to listen on every interface so
    the backend service can reach it across the Compose network, and to
    reach the instance over its private address, which is the only address
    the instance this repository provisions carries.
    """
    command = " ".join(_service(PROXY_SERVICE)["command"])
    defaulted = "${" + PROXY_INSTANCE_VARIABLE + DEFAULT_OPERATOR
    demanded = "${" + PROXY_INSTANCE_VARIABLE + REQUIRED_OPERATOR

    assert demanded in command
    assert defaulted not in command
    assert "--address=0.0.0.0" in command
    assert "--port=5432" in command
    assert "--private-ip" in command

    start = command.index(demanded) + len(demanded)
    reason = command[start:command.index("}", start)]

    assert PROXY_INSTANCE_VARIABLE in reason
    assert "project:region:instance" in reason


def test_the_proxy_runs_a_supported_release_of_the_proxy():
    """Asserts the proxy image is on the maintained v2 line.

    The v1 line reached end of support, and only v2 accepts the flags
    asserted above. The tag is pinned rather than floating so the image a
    deployment runs is the image this repository was verified against.
    """
    image = _service(PROXY_SERVICE)["image"]
    repository, _, tag = image.rpartition(":")

    assert repository == PROXY_IMAGE_REPOSITORY, image
    assert re.match(r"^2\.\d+\.\d+$", tag), image


def test_the_proxy_publishes_a_health_endpoint():
    """Asserts the proxy reports its own readiness.

    The default image is distroless and carries no shell, so no in-container
    probe can be declared for it. The proxy's own HTTP health endpoints are
    enabled instead, on every interface, so an orchestrator can read them.
    """
    command = " ".join(_service(PROXY_SERVICE)["command"])

    assert "--health-check" in command
    assert "--http-address=0.0.0.0" in command
    assert re.search(r"--http-port=\d+", command), command
    assert "healthcheck" not in _service(PROXY_SERVICE)


def test_the_proxy_selects_the_private_address():
    """Asserts the proxy connects over the instance's private address.

    The instance ``infrastructure/terraform`` declares carries no public
    IPv4 address, and this proxy connects over the public one unless the
    address type is named.
    """
    command = " ".join(_service(PROXY_SERVICE)["command"])

    # The v2 proxy image the service runs spells this --private-ip; the v1
    # image spelled it -ip_address_types=PRIVATE. Either names the same
    # control, and without one of them the proxy dials the public address.
    assert (
        "--private-ip" in command
        or "-ip_address_types=PRIVATE" in command
    ), command


def test_the_template_separates_rendering_from_starting():
    """Asserts the example file states what a verbatim copy achieves.

    A verbatim copy renders the document under either profile and starts
    only the local one, because the proxy target the gcp profile needs is
    shipped empty.
    """
    documented = ENVIRONMENT_EXAMPLE.read_text(encoding="utf-8")

    assert "renders the document under either profile" in documented
    assert "renders verbatim and does not start" in documented
    assert "starts verbatim" in documented
    assert "private address" in documented
    assert "renders and starts under either profile" not in documented


def test_every_required_variable_is_shipped_with_a_value():
    """Asserts a verbatim copy of the template renders the document.

    Compose resolves every substitution before it applies the profile
    filter, so a name marked required stops an invocation under any
    profile while the template ships that name empty. A variable only
    one profile's service consumes is defaulted rather than required.
    """
    shipped = _documented_values()
    required = _compose_required_variables()

    assert required, "the file marks a variable required"

    for name in sorted(required):
        assert name in shipped, name
        assert shipped[name].strip(), name


def test_the_file_declares_no_obsolete_version_element():
    """Asserts the document carries no top-level version key.

    Compose ignores the key and warns about it on every invocation.
    """
    assert OBSOLETE_TOP_LEVEL_KEY not in _compose_document()


def test_the_file_names_the_project_it_starts():
    """Asserts the stack declares its own project name.

    The name prefixes every container, the network and the db-data
    volume, rather than being taken from the parent directory.
    """
    assert _compose_document().get("name") == EXPECTED_PROJECT_NAME


def test_the_proxy_answers_to_the_name_the_local_database_answers_to():
    """Asserts one hostname reaches the database under either profile.

    The backend's connection string names one host, so the proxy takes
    the local service's name as a network alias rather than the backend
    carrying a second address for the gcp profile.
    """
    aliases = _service(PROXY_SERVICE)["networks"]["default"]["aliases"]

    assert "db" in aliases


def test_the_proxy_mounts_no_credential_from_this_repository():
    """Asserts the proxy authenticates with ambient credentials only."""
    proxy = _service(PROXY_SERVICE)

    assert "volumes" not in proxy
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in " ".join(
        str(value) for value in proxy.values()
    )


def test_the_frontend_target_names_the_variable_the_bundle_reads():
    """Asserts the build argument is the name the frontend source reads.

    The bundle is produced at build time and cannot read a runtime
    variable, so the value arrives as a build argument. The frontend
    source is read-only here and is the authority for the name.
    """
    source = FRONTEND_API_MODULE.read_text(encoding="utf-8")

    assert "process.env." + FRONTEND_TARGET_NAME in source
    assert FRONTEND_TARGET_NAME in dict(_build_arguments("frontend"))


def _dockerfile_of(service):
    """Returns the image definition one service builds from."""
    build = _service(service)["build"]
    context = (COMPOSE_PATH.parent / build["context"]).resolve()
    return (context / build["dockerfile"]).resolve()


def _declared_arguments_before_build(dockerfile):
    """Returns the arguments an image declares before it builds.

    Only the ``ARG`` names appearing before the first ``RUN`` that builds
    are returned, because a declaration after the build command cannot
    reach it. The scan stops at the first ``FROM`` following one, so a
    later stage's declarations are not credited to the build stage.
    """
    declared = []
    for line in dockerfile.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("ARG "):
            declared.append(stripped[4:].split("=")[0].strip())
        elif BUILD_COMMAND in stripped and stripped.startswith("RUN "):
            break
    return declared


def _exported_names(dockerfile):
    """Returns the names an image assigns with ``ENV``."""
    return re.findall(
        r"^\s*ENV\s+([A-Z][A-Z0-9_]*)=",
        dockerfile.read_text(encoding="utf-8"),
        re.MULTILINE,
    ) + re.findall(
        r"^\s+([A-Z][A-Z0-9_]*)=",
        dockerfile.read_text(encoding="utf-8"),
        re.MULTILINE,
    )


@pytest.mark.parametrize("service", BUILD_SERVICES)
def test_every_build_argument_is_declared_by_the_image_it_is_passed_to(
    service,
):
    """Asserts no build argument is passed to an image that ignores one.

    Compose drops a ``args`` entry the image never declares, silently, so
    a value passed under a name the image does not declare as an ``ARG``
    never reaches the build. Every name each service passes is therefore
    required to be declared in that service's own Dockerfile, before the
    command that builds.
    """
    passed = [name for name, _ in _build_arguments(service)]
    if not passed:
        return
    declared = _declared_arguments_before_build(_dockerfile_of(service))

    missing = [name for name in passed if name not in declared]
    assert missing == [], missing


def test_the_frontend_build_arguments_reach_the_bundle():
    """Asserts each argument is declared and exported before the build.

    Create React App reads its configuration from the build environment,
    so a declared argument additionally has to be exported for the build
    command to see it. Both names Compose passes are asserted through
    both steps.
    """
    dockerfile = _dockerfile_of("frontend")
    declared = _declared_arguments_before_build(dockerfile)
    exported = _exported_names(dockerfile)
    passed = [name for name, _ in _build_arguments("frontend")]

    assert passed
    for name in passed:
        assert name.startswith(FRONTEND_VARIABLE_PREFIX), name
        assert name in declared, name
        assert name in exported, name


def test_the_frontend_bundle_reads_every_argument_it_is_passed():
    """Asserts no build argument is passed that no source reads.

    The frontend source is read-only here and is the authority for the
    names the bundle reads, so an argument naming nothing the source
    reads is a value with no destination.
    """
    read = "".join(
        path.read_text(encoding="utf-8")
        for path in FRONTEND_CONFIGURED_MODULES
    )

    for name, _ in _build_arguments("frontend"):
        assert "process.env." + name in read, name


def test_the_frontend_targets_the_port_the_backend_listens_on():
    """Asserts one port runs through the image, the mapping and the URL.

    The address is resolved by the browser rather than by a container,
    so it names the published port on the host rather than the backend's
    Compose service name.
    """
    exposed = _exposed_port(BACKEND_DOCKERFILE)
    published, target = _service("backend")["ports"][0].split(":")
    argument = dict(_build_arguments("frontend"))[FRONTEND_TARGET_NAME]

    assert int(target) == exposed
    assert int(published) == exposed
    assert ":" + str(exposed) + "}" in argument
    assert "backend:" + str(exposed) not in argument


def test_the_frontend_publishes_the_port_its_image_exposes():
    """Asserts the frontend mapping names the port its image exposes."""
    exposed = _exposed_port(FRONTEND_DOCKERFILE)
    published, target = _service("frontend")["ports"][0].split(":")

    assert int(target) == exposed
    assert int(published) == exposed


@pytest.mark.parametrize("service", sorted(EXPECTED_PROBE_EXECUTABLE))
def test_each_probe_invokes_an_executable_its_image_provides(service):
    """Asserts the probe command names the expected executable only.

    Compose's shell form is accepted because the database probe
    interpolates the credentials it was started with, which the plain
    form cannot do. The executable is the first word either way.
    """
    probe = _service(service)["healthcheck"]["test"]

    assert probe[0] in PROBE_FORMS, probe[0]
    if probe[0] == "CMD":
        invoked = probe[1]
    else:
        invoked = probe[1].split()[0]

    assert invoked == EXPECTED_PROBE_EXECUTABLE[service]
    assert FORBIDDEN_PROBE_EXECUTABLE not in " ".join(probe)


def test_every_service_that_declares_a_probe_is_covered_here():
    """Asserts no probe escapes the executable assertion above."""
    assert set(_services_declaring_a_probe()) == set(
        EXPECTED_PROBE_EXECUTABLE
    )


def test_the_backend_probe_reads_the_readiness_route_it_serves():
    """Asserts the probe addresses the served route on the served port.

    The path asserted is the readiness route the application publishes,
    named in full rather than by prefix: the liveness path is a prefix
    of it, so a prefix match would accept either one.
    """
    probe = " ".join(_service("backend")["healthcheck"]["test"])
    exposed = _exposed_port(BACKEND_DOCKERFILE)
    served = "http://127.0.0.1:" + str(exposed) + READINESS_PATH

    assert served in probe


def test_every_frontend_argument_the_build_discards_is_recorded():
    """Asserts the discarded-argument record matches both files.

    A build argument no ``ARG`` declares is dropped by the build, so the
    bundle carries no value for it and the browser falls back on the
    source default. The set the frontend image drops is asserted to equal
    :data:`DISCARDED_FRONTEND_ARGUMENTS` exactly, in both directions: an
    argument added to the Compose file with no ``ARG`` to receive it
    fails here, and so does a name left in the record after the image
    began declaring it. While the set is non-empty the Compose file is
    asserted to say so beside the arguments themselves, which is what
    stops its build stanza reading as a delivery the build does not make.
    """
    supplied = set(name for name, _ in _build_arguments("frontend"))
    discarded = supplied - _declared_image_arguments(FRONTEND_DOCKERFILE)

    assert discarded == set(DISCARDED_FRONTEND_ARGUMENTS), sorted(discarded)
    if discarded:
        assert DISCARDED_ARGUMENT_NOTE in _compose_text()


def test_the_setup_script_declares_each_readonly_name_once():
    """Asserts no name is declared ``readonly`` twice.

    The second declaration of one name returns non-zero under every
    shell, and the script's own options end the run at that line, so a
    duplicate leaves the whole setup unperformed.
    """
    declared = READONLY_DECLARATION.findall(_setup_script_text())
    assert declared, SETUP_SCRIPT.name

    repeated = sorted(
        name for name in set(declared) if declared.count(name) > 1
    )

    assert repeated == []


def test_the_setup_script_bootstrap_runs_without_failing():
    """Runs the setup script's declarations, definitions and traps.

    The entry point is removed first, so nothing is installed, written,
    created or migrated. An empty standard output is asserted alongside
    the exit status: every step of the setup announces itself, so silence
    is the evidence that none of them ran. The shell is abandoned after
    :data:`BOOTSTRAP_TIMEOUT_SECONDS`.
    """
    shell = shutil.which("bash")
    if shell is None:
        pytest.skip("no POSIX shell is available to run the bootstrap")

    with tempfile.TemporaryDirectory() as directory:
        bootstrap = Path(directory) / SETUP_SCRIPT.name
        bootstrap.write_bytes(_setup_script_bootstrap().encode("utf-8"))
        try:
            completed = subprocess.run(
                [shell, str(bootstrap)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=BOOTSTRAP_TIMEOUT_SECONDS,
            )
        except subprocess.TimeoutExpired as expired:
            raise AssertionError(
                "{0} did not finish its bootstrap within {1} seconds; "
                "stdout={2!r} stderr={3!r}".format(
                    SETUP_SCRIPT.name,
                    BOOTSTRAP_TIMEOUT_SECONDS,
                    expired.stdout,
                    expired.stderr,
                )
            ) from None

    assert completed.returncode == 0, completed.stderr.decode(
        "utf-8", "replace"
    )
    assert completed.stdout == b""


# ---------------------------------------------------------------------
# The pipeline and infrastructure contract
# ---------------------------------------------------------------------

#: Continuous-integration workflow: the complete verification gate.
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Continuous-deployment workflow.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"

#: Terraform module provisioning the cluster, database and secrets.
TERRAFORM_MAIN = REPO_ROOT / "infrastructure" / "terraform" / "main.tf"

#: Terraform variable declarations.
TERRAFORM_VARIABLES = (
    REPO_ROOT / "infrastructure" / "terraform" / "variables.tf"
)

#: Script that deploys a built image to the cluster.
DEPLOY_SCRIPT = REPO_ROOT / "scripts" / "deploy.sh"

#: Name of the workflow a deployment is gated on.
GATING_WORKFLOW_NAME = "CI"

#: Repository variable naming the runner the cluster jobs execute on.
CLUSTER_RUNNER_VARIABLE = "GKE_DEPLOY_RUNNER_LABEL"

#: Runner images GitHub hosts. None of them sits inside the VPC, so a
#: cluster job naming one could not reach the private control plane.
HOSTED_RUNNER_LABELS = (
    "ubuntu-latest",
    "ubuntu-24.04",
    "ubuntu-22.04",
    "ubuntu-20.04",
    "windows-latest",
    "windows-2025",
    "windows-2022",
    "windows-2019",
    "macos-latest",
    "macos-15",
    "macos-14",
    "macos-13",
)

#: Command that reaches the Kubernetes API server.
CLUSTER_COMMAND = "kubectl"

#: Flags that address the regional cluster main.tf creates. --location
#: accepts a region and a zone alike; --region accepts a region only, so
#: either one addresses a regional cluster and neither addresses a zonal
#: one by itself. The delivered workflow uses --region.
CLUSTER_LOCATION_FLAGS = ("--location", "--region")

#: Flag that addresses a zonal cluster only.
ZONAL_LOCATION_FLAG = "--zone"

#: Environment names that may carry the cluster location in the workflow.
#: Either spelling names the same regional value; the delivered workflow
#: uses GKE_REGION, whose value the kubernetes_cluster_location output
#: carries.
CLUSTER_LOCATION_NAMES = ("GKE_LOCATION", "GKE_REGION")

#: Access scope the node pool carries. It is a ceiling on the tokens a
#: node may mint; the IAM roles below are what bound the identity.
NODE_ACCESS_SCOPE = "https://www.googleapis.com/auth/cloud-platform"

#: Roles the node identity needs to read the images it runs. One of them
#: is enough, since a gcr.io name resolves to Artifact Registry in a
#: redirected project and to Cloud Storage in one that is not.
IMAGE_READ_ROLES = (
    "roles/artifactregistry.reader",
    "roles/storage.objectViewer",
)

#: Terraform expressions the private control plane is declared by.
PRIVATE_CLUSTER_DECLARATIONS = (
    r"enable_private_nodes\s*=\s*true",
    r"enable_private_endpoint\s*=\s*true",
)

#: Runtime pin, and the expression each pin site carries it in. The
#: interpreter is a hard constraint, so every one of them is asserted.
RUNTIME_PIN_SITES = {
    "ci.yml": (CI_WORKFLOW, r"python-version:\s*'3\.9'"),
    "main.tf": (TERRAFORM_MAIN, r'runtime\s*=\s*"python39"'),
    "deploy.sh": (DEPLOY_SCRIPT, r"--runtime python39"),
    "Dockerfile.backend": (
        BACKEND_DOCKERFILE,
        r"FROM python:3\.9-slim",
    ),
}

#: Flag that would publish the Cloud Function to anyone on the internet.
PUBLIC_INVOCATION_FLAG = "--allow-unauthenticated"

#: Flag that withholds it. It carries the forbidden one as a suffix, so a
#: search for the forbidden flag excludes this spelling before matching.
PRIVATE_INVOCATION_FLAG = "--no-allow-unauthenticated"

#: Migration command the deployment applies the schema with.
MIGRATION_COMMAND = "alembic"

#: In-place image mutation. Neither delivery path issues one any longer --
#: it changes a single field of whatever the cluster happens to hold and
#: leaves every other property as it was found -- so the constant is
#: retained as the construct the cases below assert the absence of.
ROLLOUT_COMMAND = "kubectl set image"

#: Every way a release changes what a Deployment serves. Both paths render
#: the manifests, which already carry this release's digest, so applying them
#: is the rollout. The in-place mutation is kept in the inventory so that a
#: path that reintroduced it would still be ordered against the migration.
#: The two spellings of the same renderer invocation. The workflow names
#: the script by its repository-relative path; the release script holds that
#: path in one constant and invokes it through the constant, so both are
#: read wherever the rollout has to be located.
ROLLOUT_RENDERS = (
    "render_kubernetes_manifests.sh workloads",
    '"${RENDER}" workloads',
)

ROLLOUT_COMMANDS = (ROLLOUT_COMMAND,) + ROLLOUT_RENDERS

#: Deployments the pipeline and the script both address.
SERVING_DEPLOYMENTS = ("deployment/frontend", "deployment/backend")

#: Job the verification gate runs in.
CI_JOB = "backend"

#: Script that carries the secret and ignore policy, and the step that
#: invokes it.
SECRET_POLICY_SCRIPT = (
    REPO_ROOT / ".github" / "scripts" / "check_secret_policy.sh"
)

SECRET_POLICY_INVOCATION = "check_secret_policy.sh"

#: Node major the committed lockfile supports. The lockfile declares
#: ``engines.node >= 18``, so a major below that cannot install it.
MIN_SUPPORTED_NODE_MAJOR = 18

#: Frontend manifest. It is read-only here, and is the authority for which
#: npm scripts exist: the workflow may invoke no script it does not
#: declare.
FRONTEND_MANIFEST = REPO_ROOT / "frontend" / "package.json"

#: Lockfile, the authority for the supported Node major.
FRONTEND_LOCKFILE = REPO_ROOT / "frontend" / "package-lock.json"

#: Shape of one ``npm run <script>`` invocation.
NPM_SCRIPT_CALL = re.compile(r"npm\s+run\s+([A-Za-z0-9_:-]+)")

#: Marker of work left for a person to finish. A verification gate that
#: carries one is not a gate.
DEFERRED_WORK_MARKERS = (
    "HUMAN ASSISTANCE NEEDED",
    "TODO",
    "FIXME",
)

#: Database service the production-dialect tests run against, and the
#: major it must pin -- the one Compose and Terraform both pin.
CI_DATABASE_SERVICE = "postgres"

CI_DATABASE_IMAGE_MAJOR = "postgres:13"

#: Names the production-dialect fixtures read, and the value the second
#: must carry so an unreachable server fails the job rather than skipping.
POSTGRES_URL_VARIABLE = "POSTGRES_TEST_URL"

POSTGRES_REQUIRED_VARIABLE = "REQUIRE_POSTGRES_TESTS"

#: Marker naming the cases that need that server.
POSTGRES_MARKER = "postgres"

#: Advisory registers, and the authority each is recorded in. The runtime
#: set is documented in the residual-risk register; the development set is
#: documented in the manifest that declares it, because the residual-risk
#: register covers the deployed artifact alone.
RUNTIME_ADVISORIES = (
    "PYSEC-2026-161",
    "PYSEC-2026-248",
    "PYSEC-2026-249",
    "PYSEC-2026-2280",
    "PYSEC-2026-2281",
    "PYSEC-2026-2270",
    "PYSEC-2026-2132",
)

DEVELOPMENT_ADVISORIES = (
    "PYSEC-2026-1845",
    "PYSEC-2026-3625",
    "PYSEC-2026-1374",
    "PYSEC-2026-1375",
    "PYSEC-2026-2275",
    "PYSEC-2026-141",
    "PYSEC-2026-142",
)

RESIDUAL_RISK_REGISTER = (
    REPO_ROOT / "docs" / "security" / "RESIDUAL_RISK.md"
)

DEVELOPMENT_MANIFEST = REPO_ROOT / "backend" / "requirements-dev.txt"


def _workflow_document(path):
    """Returns one parsed workflow document."""
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _workflow_triggers(document):
    """Returns the trigger mapping of a parsed workflow.

    YAML 1.1 reads a bare ``on`` as the boolean true, so the key is
    looked up under both spellings.
    """
    if "on" in document:
        return document["on"]
    return document[True]


def _cd_document():
    """Returns the parsed deployment workflow."""
    return _workflow_document(CD_WORKFLOW)


def _cd_text():
    """Returns the deployment workflow as text."""
    return CD_WORKFLOW.read_text(encoding="utf-8")


def _terraform_text():
    """Returns the Terraform module as text."""
    return TERRAFORM_MAIN.read_text(encoding="utf-8")


def _terraform_variables_text():
    """Returns the Terraform variable declarations as text."""
    return TERRAFORM_VARIABLES.read_text(encoding="utf-8")


def _deploy_script_text():
    """Returns the deployment script as text."""
    return DEPLOY_SCRIPT.read_text(encoding="utf-8")


def _job_steps(job):
    """Returns the steps of one parsed job."""
    return job.get("steps") or []


def _step_text(step):
    """Returns everything one step would execute or configure."""
    parts = [str(step.get("run") or ""), str(step.get("uses") or "")]
    for name, value in (step.get("with") or {}).items():
        parts.append("{0}={1}".format(name, value))
    for name, value in (step.get("env") or {}).items():
        parts.append("{0}={1}".format(name, value))
    return "\n".join(parts)


def _step_commands(step):
    """Returns the shell of one step with its comment lines removed.

    A comment naming a command is documentation rather than a call, so it
    is dropped before any of the checks below look for one.
    """
    return "\n".join(
        line
        for line in str(step.get("run") or "").splitlines()
        if not line.lstrip().startswith("#")
    )


def _job_commands(job):
    """Returns the shell of one job with its comment lines removed."""
    return "\n".join(_step_commands(step) for step in _job_steps(job))


#: Shape of one call that reaches the Kubernetes API server.
CLUSTER_CALL = re.compile(
    r"^\s*(?:if\s+!\s+)?" + CLUSTER_COMMAND + r"\b", re.MULTILINE
)


def _cluster_jobs(document):
    """Returns the jobs that reach the Kubernetes API server."""
    return dict(
        (name, job)
        for name, job in document["jobs"].items()
        if CLUSTER_CALL.search(_job_commands(job))
    )


def _gated_jobs(document, condition_fragment):
    """Returns the jobs reached from one carrying ``condition_fragment``.

    A job is reached when it carries the fragment in its own ``if``, or
    when its ``needs`` chain arrives at a job that does.
    """
    jobs = document["jobs"]
    gated = set(
        name
        for name, job in jobs.items()
        if condition_fragment in str(job.get("if", ""))
    )
    changed = True
    while changed:
        changed = False
        for name, job in jobs.items():
            if name in gated:
                continue
            needs = job.get("needs") or []
            if isinstance(needs, str):
                needs = [needs]
            if any(required in gated for required in needs):
                gated.add(name)
                changed = True
    return gated


def _step_index(job, fragment):
    """Returns the index of the first step whose shell holds ``fragment``.

    ``fragment`` may be a tuple, in which case a step holding any one of
    its members matches -- which is how one assertion covers two spellings
    of the same act. ``-1`` is returned when no step holds it. Comment
    lines are excluded, so an ordering assertion reads calls rather than
    prose.
    """
    wanted = fragment if isinstance(fragment, tuple) else (fragment,)
    for index, step in enumerate(_job_steps(job)):
        commands = _step_commands(step)
        if any(one in commands for one in wanted):
            return index
    return -1


def test_the_deployment_is_triggered_by_the_verification_workflow():
    """Asserts deployment follows a completed run of the CI workflow.

    The complete gate is CI, so the deployment workflow is triggered by
    its completion rather than by the push, and it declares no push
    trigger of its own that would bypass it.
    """
    triggers = _workflow_triggers(_cd_document())

    assert "workflow_run" in triggers, sorted(triggers)
    assert "push" not in triggers, sorted(triggers)
    assert triggers["workflow_run"]["workflows"] == [
        GATING_WORKFLOW_NAME
    ]
    assert _workflow_document(CI_WORKFLOW)["name"] == (
        GATING_WORKFLOW_NAME
    )


def test_every_deployment_job_is_gated_on_that_run_succeeding():
    """Asserts no job runs unless the gating run concluded successfully."""
    document = _cd_document()
    gated = _gated_jobs(document, "conclusion == 'success'")

    assert set(document["jobs"]) == gated, sorted(
        set(document["jobs"]) - gated
    )


def test_the_deployment_workflow_verifies_nothing_of_its_own():
    """Asserts the workflow carries no second copy of the CI gate.

    A gate duplicated here could drift from the one in CI, so the
    deployment workflow runs none of the verification commands itself.
    """
    text = _cd_text()
    for command in ("pip-audit", "bandit", "flake8", "pytest"):
        assert command not in text, command


def test_the_cluster_jobs_run_on_a_runner_inside_the_network():
    """Asserts every job reaching the cluster names the private runner.

    The control plane carries no public endpoint, so a job that reaches
    it runs on the self-hosted runner the repository variable names,
    never on a hosted image.
    """
    document = _cd_document()
    cluster_jobs = _cluster_jobs(document)

    assert cluster_jobs, sorted(document["jobs"])
    for name, job in cluster_jobs.items():
        runner = str(job.get("runs-on", ""))
        assert CLUSTER_RUNNER_VARIABLE in runner, (name, runner)
        for label in HOSTED_RUNNER_LABELS:
            assert runner != label, (name, runner)


def test_a_hosted_runner_label_is_refused_before_anything_is_deployed():
    """Asserts the workflow refuses a hosted label rather than trying it.

    Every hosted image the check knows about is named in the workflow, so
    a variable set to one of them stops the run with a message instead of
    failing at the first cluster call.
    """
    text = _cd_text()
    for label in HOSTED_RUNNER_LABELS:
        assert label in text, label


def test_the_cluster_is_addressed_by_one_location_value():
    """Asserts the workflow and Terraform agree on the cluster location.

    Terraform creates a regional cluster from ``var.region``, and the
    workflow fetches credentials with the flag that accepts a region.
    """
    text = _cd_text()

    assert any(flag in text for flag in CLUSTER_LOCATION_FLAGS), (
        CLUSTER_LOCATION_FLAGS
    )
    assert ZONAL_LOCATION_FLAG not in text
    assert any(name in text for name in CLUSTER_LOCATION_NAMES), (
        CLUSTER_LOCATION_NAMES
    )
    assert "GKE_ZONE" not in text
    assert re.search(
        r"resource\s+\"google_container_cluster\"[^}]*?"
        r"location\s*=\s*var\.region",
        _terraform_text(),
        re.S,
    )


def test_each_image_is_built_from_the_definition_that_declares_it():
    """Asserts every build names its Dockerfile and its own context.

    Neither ``./frontend`` nor ``./backend`` holds a Dockerfile, so a
    build that named only a context would find none.
    """
    text = _cd_text()
    for dockerfile, context in (
        (FRONTEND_DOCKERFILE, "./frontend"),
        (BACKEND_DOCKERFILE, "./backend"),
    ):
        relative = "infrastructure/docker/" + dockerfile.name
        assert "-f {0}".format(relative) in text.replace(
            "\\\n", ""
        ).replace("  ", " "), relative
        assert context in text, context


def test_the_schema_is_migrated_before_anything_new_serves():
    """Asserts the rollout step follows the migration step.

    A migration that fails therefore leaves the previous image serving.
    """
    document = _cd_document()
    for name, job in _cluster_jobs(document).items():
        migration = _step_index(job, MIGRATION_COMMAND)
        rollout = _step_index(job, ROLLOUT_COMMANDS)
        if migration < 0 and rollout < 0:
            continue
        assert migration >= 0, name
        assert rollout >= 0, name
        assert migration < rollout, (name, migration, rollout)


def test_a_failed_migration_stops_the_deployment():
    """Asserts the migration step exits non-zero when it did not succeed."""
    document = _cd_document()
    for job in _cluster_jobs(document).values():
        index = _step_index(job, MIGRATION_COMMAND)
        if index < 0:
            continue
        body = _step_text(_job_steps(job)[index])
        # The migration is a Job whose completion is waited on rather than
        # a pod whose phase is polled, so the outcome is read from the wait
        # rather than from a phase comparison. Either form is accepted; what
        # is asserted is that a migration which did not succeed exits
        # non-zero instead of letting the rollout follow it.
        assert (
            'if [ "$phase" != "Succeeded" ]' in body
            or "--for=condition=complete" in body
        ), body
        assert "exit 1" in body


def test_the_control_plane_is_probed_before_it_is_changed():
    """Asserts reachability is checked before any cluster mutation."""
    document = _cd_document()
    for name, job in _cluster_jobs(document).items():
        probe = _step_index(job, "kubectl version")
        rollout = _step_index(job, ROLLOUT_COMMANDS)
        if rollout < 0:
            continue
        assert probe >= 0, name
        assert probe < rollout, (name, probe, rollout)


def test_the_node_pool_carries_the_scope_its_image_pulls_need():
    """Asserts the node pool's access scope admits an image pull.

    An access scope is a ceiling over IAM, so a node whose scopes name
    only logging and monitoring cannot use a registry-read role it holds.
    """
    text = _terraform_text()
    scopes = re.search(r"oauth_scopes\s*=\s*(?P<value>\S+)", text)
    assert scopes is not None, "the node pool declares no access scope"

    #: The list arrives through var.gke_node_oauth_scopes rather than as a
    #: literal, so the scope is read from that variable's default and its
    #: validation. The validation is the stronger control: it refuses any
    #: list that would leave the pool unable to reach the registry, which a
    #: literal cannot do.
    declared = scopes.group("value")
    if declared.startswith("var."):
        variable = re.search(
            r'(?s)variable\s+"'
            + declared[len("var."):]
            + r'"\s*\{(?P<body>.*?)\n\}',
            _terraform_variables_text(),
        )
        assert variable is not None, declared
        body = variable.group("body")
        assert NODE_ACCESS_SCOPE in body, body
        default = re.search(
            r"(?s)default\s*=\s*\[(?P<items>.*?)\]", body
        )
        assert default is not None, body
        assert NODE_ACCESS_SCOPE in default.group("items")
        assert "logging.write" not in default.group("items")
    else:
        assert NODE_ACCESS_SCOPE in declared


def test_the_node_identity_may_read_the_registry_it_pulls_from():
    """Asserts the node service account holds a registry-read role."""
    text = _terraform_variables_text()
    granted = re.search(
        r"variable\s+\"gke_node_service_account_roles\".*?default\s*=\s*"
        r"\[(?P<body>.*?)\]",
        text,
        re.S,
    )

    assert granted is not None
    assert any(
        role in granted.group("body") for role in IMAGE_READ_ROLES
    ), granted.group("body")


def test_the_control_plane_keeps_no_public_endpoint():
    """Asserts the private-cluster declarations are both in place."""
    text = _terraform_text()
    for declaration in PRIVATE_CLUSTER_DECLARATIONS:
        assert re.search(declaration, text), declaration


def test_at_least_one_authorized_network_is_required():
    """Asserts the authorized-network list cannot be left empty.

    With no public endpoint and no authorized network, nothing outside
    the node subnet could reach the control plane.
    """
    text = _terraform_variables_text()
    declaration = re.search(
        r"variable\s+\"gke_master_authorized_networks\".*?\n}\n",
        text,
        re.S,
    )

    assert declaration is not None
    body = declaration.group(0)
    assert "default" not in body, body
    assert (
        "length(var.gke_master_authorized_networks) > 0" in body
    ), body


def test_the_deploy_script_stops_at_the_first_failure():
    """Asserts the script sets the shell options that stop it.

    The delivered script adds ``-E`` so its ERR trap reaches inside every
    function, so the options are read individually rather than as one
    literal spelling.
    """
    text = _deploy_script_text()
    options = re.search(r"^set -([A-Za-z]+) pipefail$", text, re.M)

    assert options is not None, "the script sets no shell options"
    for option in ("e", "u", "o"):
        assert option in options.group(1), (option, options.group(0))


def test_the_deploy_script_builds_from_the_real_definitions():
    """Asserts the script names both image definitions and contexts."""
    text = _deploy_script_text()
    for dockerfile in (FRONTEND_DOCKERFILE, BACKEND_DOCKERFILE):
        assert (
            "infrastructure/docker/" + dockerfile.name in text
        ), dockerfile.name
    # One build path serves every workload in the release inventory,
    # reading each one's definition from the table above, so the -f flag
    # appears once rather than once per image. What is asserted is that no
    # build relies on a default definition inside its context, since
    # neither context holds one.
    build_at = text.index("docker build")
    invocation = text[build_at:build_at + 400]

    assert "-f " in invocation or "--file " in invocation, invocation
    assert "WORKLOAD_DOCKERFILE" in text


def test_the_deploy_script_addresses_the_serving_deployments():
    """Asserts the script names the Deployments the workflow names."""
    text = _deploy_script_text()
    # The script addresses the inventory through one expression rather
    # than naming each Deployment at every call site, so each workload is
    # asserted to be in that inventory and the expression to be the object
    # every cluster call is made against.
    assert 'deployment/${workload}' in text
    for deployment in SERVING_DEPLOYMENTS:
        workload = deployment.split("/", 1)[1]
        assert re.search(
            r"RELEASE_WORKLOADS=\([^)]*\b%s\b" % re.escape(workload),
            text,
            re.S,
        ), workload
    assert "app-deployment" not in text


def test_the_deploy_script_migrates_before_it_rolls_out():
    """Asserts the migration precedes the rollout in the script.

    The rollout is read from :data:`ROLLOUT_COMMANDS` rather than from the
    in-place mutation alone: the script renders the serving manifests, which
    already carry this release's digests, so applying them is what rolls the
    release out and no image is set on a running object.
    """
    text = _deploy_script_text()
    migration = text.index(MIGRATION_COMMAND)
    rollouts = [
        text.index(command) for command in ROLLOUT_COMMANDS if command in text
    ]

    assert rollouts, ROLLOUT_COMMANDS
    assert ROLLOUT_COMMAND not in text, (
        "the script mutates a running Deployment's image instead of applying "
        "the manifests that carry the digest"
    )
    assert migration < min(rollouts), (migration, rollouts)
    #: The migration is a Job, so completion is what is waited on and a
    #: failure is reported from the Job rather than from a pod phase.
    assert "--for=condition=complete" in text
    assert "did not complete." in text


def test_the_deploy_script_deploys_no_function_without_a_source():
    """Asserts the function step checks its inputs before it runs."""
    text = _deploy_script_text()

    # The function is deployed from a published archive rather than from a
    # working-tree directory, and the step is additionally withheld until a
    # release owner authorizes it. The claim is unchanged and is met more
    # strictly: the step checks its inputs and deploys nothing when they
    # are not satisfied.
    assert "CLOUD_FUNCTION_SOURCE_OBJECT" in text
    assert 'FUNCTION_SOURCE=""' in text
    assert '--source="${FUNCTION_SOURCE}"' in text
    gate = re.search(
        r'if \[ "\$\{CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED\}" '
        r'!= "true" \];.*?\n    fi\n',
        text,
        re.S,
    )
    assert gate is not None, "the function step carries no authorization gate"
    assert "return 0" in gate.group(0), gate.group(0)
    assert text.index("CLOUD_FUNCTION_DEPLOYMENT_AUTHORIZED") < text.index(
        "gcloud functions deploy"
    )
    assert "function-name" not in text
    assert "./functions" not in text


def test_no_deployment_publishes_the_function_to_everyone():
    """Asserts the unauthenticated-invocation flag appears nowhere.

    The flag that withholds invocation carries the forbidden one as a
    suffix, so it is removed before the search is made.
    """
    for path in (DEPLOY_SCRIPT, CD_WORKFLOW, TERRAFORM_MAIN):
        # Comments are dropped first. The flag is named in prose where the
        # binding that would have carried it is documented as removed, and
        # what is forbidden is a command passing it, not a sentence about
        # it.
        text = "\n".join(
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if not line.lstrip().startswith(("#", "//"))
        ).replace(PRIVATE_INVOCATION_FLAG, "")
        assert PUBLIC_INVOCATION_FLAG not in text, path.name
    assert PRIVATE_INVOCATION_FLAG in _deploy_script_text()


@pytest.mark.parametrize("site", sorted(RUNTIME_PIN_SITES))
def test_the_runtime_pin_is_still_carried_at_every_site(site):
    """Asserts each pin site still names the pinned interpreter."""
    path, expression = RUNTIME_PIN_SITES[site]
    assert re.search(
        expression, path.read_text(encoding="utf-8")
    ), (site, expression)


#: Documents that quote a pin site by line number, and the construct each
#: quoted line must hold. A line reference drifts whenever the file around
#: it changes, and these had drifted before this assertion existed.
DOCUMENTED_PIN_CITATIONS = (
    REPO_ROOT / "docs" / "review" / "CRITICAL_DECISIONS.md",
    REPO_ROOT / "docs" / "security" / "RESIDUAL_RISK.md",
)

#: The construct each pin site carries, by repository-relative path. A
#: citation naming one of these paths with a line number is checked
#: against the line that number selects.
PIN_CONSTRUCT_BY_PATH = {
    "infrastructure/docker/Dockerfile.backend": "python:3.9-slim",
    ".github/workflows/ci.yml": "python-version",
    "infrastructure/terraform/main.tf": "python39",
    "scripts/deploy.sh": "python39",
    "backend/app/tasks/listing_updater.py": "asyncio.coroutine",
}

#: Shape of one ``path:line`` citation inside a document.
PIN_CITATION = re.compile(
    r"`?(" + "|".join(
        re.escape(name) for name in sorted(PIN_CONSTRUCT_BY_PATH)
    ) + r"):(\d+)`?"
)


#: Shape of one pin-site table row, which cites the same thing in two
#: cells instead of one: the path in the first and the line in the
#: second. A row had drifted on three of its four numbers while the prose
#: citations beside it were correct, so both forms are read.
PIN_TABLE_CITATION = re.compile(
    r"\|\s*`(" + "|".join(
        re.escape(name) for name in sorted(PIN_CONSTRUCT_BY_PATH)
    ) + r")`\s*\|\s*(\d+)\s*\|"
)


def _documented_pin_citations(document):
    """Returns every pin citation one document makes, in either form."""
    text = document.read_text(encoding="utf-8")

    return PIN_CITATION.findall(text) + PIN_TABLE_CITATION.findall(text)


@pytest.mark.parametrize(
    "document", DOCUMENTED_PIN_CITATIONS, ids=lambda path: path.name
)
def test_every_documented_pin_site_line_is_correct(document):
    """Each line number a document quotes still holds its construct.

    The runtime pin is a hard constraint, so the documents that present it
    to a reviewer quote the exact line to look at. Those numbers move
    whenever the file around them changes, and a reviewer sent to the
    wrong line cannot perform the check being asked of them. This reads
    each citation, opens the file and asserts the numbered line carries
    the construct -- so a moved pin fails here rather than misdirecting a
    reviewer.
    """
    citations = _documented_pin_citations(document)

    assert citations, document.name
    for path_name, quoted in citations:
        expected = PIN_CONSTRUCT_BY_PATH[path_name]
        lines = (REPO_ROOT / path_name).read_text(
            encoding="utf-8"
        ).splitlines()
        number = int(quoted)
        assert 1 <= number <= len(lines), (path_name, number)
        assert expected in lines[number - 1], (
            document.name, path_name, number, lines[number - 1]
        )


#: Review artefact that presents the advisory acceptance to a reviewer.
CRITICAL_DECISIONS = (
    REPO_ROOT / "docs" / "review" / "CRITICAL_DECISIONS.md"
)


def test_the_review_document_qualifies_the_advisory_count():
    """The seven is named as the runtime figure, not as the total.

    Two manifests are audited and fourteen identifiers are suppressed, so
    an unqualified "seven residual advisories" understates the total by
    half and points a reviewer at a register that records only one of the
    two sets.
    """
    text = CRITICAL_DECISIONS.read_text(encoding="utf-8")

    assert "runtime manifest" in text
    assert "requirements-dev.txt" in text
    assert "fourteen" in text


def test_the_review_document_names_both_registers_and_their_authorities():
    """Each register is pointed at the document that records it."""
    text = CRITICAL_DECISIONS.read_text(encoding="utf-8")
    runtime_at = text.index("requirements.txt")
    development_at = text.index("requirements-dev.txt")

    assert runtime_at < development_at
    assert RESIDUAL_RISK_REGISTER.name in text


#: Heading opening the register's accepted-advisory section, and the one
#: that closes it. The section between them is the accepted set; an
#: identifier named elsewhere in the document is history rather than an
#: acceptance -- the three eliminated by removing `requests` and `urllib3`
#: are recorded under a later heading, which is correct.
ACCEPTED_SECTION_START = (
    "## Runtime register: seven accepted runtime advisories"
)

ACCEPTED_SECTION_END = "## Proof that no fix is reachable"


def _accepted_section():
    """Returns the register's accepted-advisory section alone."""
    text = RESIDUAL_RISK_REGISTER.read_text(encoding="utf-8")
    start = text.index(ACCEPTED_SECTION_START)
    end = text.index(ACCEPTED_SECTION_END, start)
    return text[start:end]


@pytest.mark.parametrize("advisory", RUNTIME_ADVISORIES)
def test_each_runtime_advisory_is_accepted_in_the_register(advisory):
    """Every identifier the runtime step suppresses is accepted there."""
    assert advisory in _accepted_section(), advisory


@pytest.mark.parametrize("advisory", DEVELOPMENT_ADVISORIES)
def test_no_development_advisory_is_accepted_in_the_runtime_register(
    advisory,
):
    """The accepted set is the runtime set alone.

    Accepting a development identifier there would make the register's own
    count disagree with the manifest it describes. An identifier may still
    appear elsewhere in the document as a disposition -- three of these
    were eliminated by removing `requests` and `urllib3` from the runtime,
    and recording that is correct -- so only the accepted section is read.
    """
    assert advisory not in _accepted_section(), advisory


def test_the_accepted_section_names_no_advisory_beyond_the_runtime_set():
    """The accepted set is exactly seven, with nothing unaccounted for."""
    named = set(re.findall(r"PYSEC-\d{4}-\d+", _accepted_section()))

    assert named == set(RUNTIME_ADVISORIES), sorted(
        named.symmetric_difference(RUNTIME_ADVISORIES)
    )


def test_the_development_manifest_carries_its_own_register():
    """The development set is documented where the gate points.

    The manifest enumerated the identifiers itself while the register
    enumerated them too, which is one set of facts in two places. The
    register is now the only enumeration and the manifest points at it, so
    what is asserted here is that the pointer resolves and that the register
    it names carries every identifier the development gate suppresses.
    """
    text = DEVELOPMENT_MANIFEST.read_text(encoding="utf-8")
    register = RESIDUAL_RISK_REGISTER.read_text(encoding="utf-8")

    assert "Development register" in text
    assert RESIDUAL_RISK_REGISTER.name in text
    for advisory in DEVELOPMENT_ADVISORIES:
        assert advisory in register, advisory


#: Bidirectional traceability matrix.
TRACEABILITY_MATRIX = (
    REPO_ROOT / "docs" / "security" / "TRACEABILITY_MATRIX.md"
)

#: Heading of the matrix section that states each finding's verification
#: status, and the heading that closes it.
STATUS_SECTION_START = "## 8. Verification status"

STATUS_SECTION_END = "## 9. The delivery-surface review"

#: Statuses the section is permitted to record.
PERMITTED_STATUSES = ("PASS", "PARTIAL", "FAIL")

#: Directory the suite's modules live under.
TEST_ROOT = REPO_ROOT / "backend" / "tests"


def _status_section():
    """Returns the matrix's verification-status section alone."""
    text = TRACEABILITY_MATRIX.read_text(encoding="utf-8")
    start = text.index(STATUS_SECTION_START)
    return text[start:text.index(STATUS_SECTION_END, start)]


def _cited_test_modules(section):
    """Returns every ``test_*.py`` module name the section cites."""
    return set(re.findall(r"`(test_[A-Za-z0-9_]+\.py)`", section))


def _cited_test_functions(section):
    """Returns every ``test_*`` function name the section cites."""
    functions = set(re.findall(r"`(test_[A-Za-z0-9_]+)`", section))
    return functions - set(
        name[: -len(".py")] for name in _cited_test_modules(section)
    )


def _defined_test_functions():
    """Returns every test function name the suite defines."""
    defined = set()
    pattern = re.compile(
        r"^\s*(?:async\s+)?def (test_[A-Za-z0-9_]+)", re.MULTILINE
    )
    for module in TEST_ROOT.rglob("test_*.py"):
        defined.update(
            pattern.findall(module.read_text(encoding="utf-8"))
        )
    return defined


def test_every_assertion_the_matrix_cites_exists():
    """A cited assertion resolves to one the suite actually defines.

    The matrix's claim is that each finding is reached by an assertion, so
    a name that resolves to nothing is the same defect the count-based
    completeness statement had -- a filled cell standing in for evidence.
    """
    section = _status_section()
    cited = _cited_test_functions(section)
    defined = _defined_test_functions()

    assert cited
    assert cited <= defined, sorted(cited - defined)


def test_every_module_the_matrix_cites_exists():
    """A cited module resolves to a file under the test tree."""
    section = _status_section()
    cited = _cited_test_modules(section)

    assert cited
    for name in sorted(cited):
        assert list(TEST_ROOT.rglob(name)), name


def test_the_matrix_records_a_status_for_every_finding():
    """Each of the twenty findings carries one permitted status."""
    section = _status_section()
    rows = [
        line
        for line in section.splitlines()
        if line.startswith("| **") and "|" in line[3:]
    ]

    assert len(rows) == 20, len(rows)
    for row in rows:
        cells = [cell.strip() for cell in row.strip("|").split("|")]
        status = cells[1].strip("* ")
        assert status in PERMITTED_STATUSES, (cells[0], status)


#: Number words the status prose may use to tally its own rows, indexed by
#: the number each spells.
STATUS_TALLY_WORDS = {
    "zero": 0,
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
}


def _tallied_statuses():
    """Returns how many rows carry each status, tallied from the table."""
    counts = dict.fromkeys(PERMITTED_STATUSES, 0)
    for line in _status_section().splitlines():
        if not line.startswith("| **") or "|" not in line[3:]:
            continue
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        counts[cells[1].strip("* ")] += 1
    return counts


def test_the_status_prose_tallies_its_own_table():
    """A status count stated in prose matches the rows it describes.

    The section's prose summarises the table it follows, and a summary
    that disagrees with its own rows is the failure mode this document
    exists to avoid -- a reader trusting the sentence over the evidence.
    Both numbers are asserted against the tallied rows so neither can be
    edited without the other.
    """
    prose = " ".join(_status_section().split())
    tallied = _tallied_statuses()

    for status in ("PASS", "PARTIAL"):
        stated = re.findall(
            r"\b([A-Za-z]+)(?:\s+findings)?\s+are\s+"
            + status
            + r"\b",
            prose,
        )
        spelled = [
            STATUS_TALLY_WORDS[word.lower()]
            for word in stated
            if word.lower() in STATUS_TALLY_WORDS
        ]
        assert spelled, (status, prose[:400])
        for number in spelled:
            assert number == tallied[status], (
                status,
                number,
                tallied,
            )


def test_the_matrix_claims_no_completeness_from_counting():
    """Completeness is no longer asserted from counts or filled cells.

    The counts themselves are kept as a reconciliation against the plan,
    so what is asserted here is that the verification section does not
    offer them as proof that a control is verified.
    """
    # The document is hard-wrapped, so a phrase spanning a line break
    # would not be found in the raw text. Whitespace is collapsed first.
    prose = " ".join(_status_section().split())

    assert "not evidence that a control is verified" in prose
    assert "an assertion that reaches the control" in prose
    assert "not a filled cell in a table" in prose


# ---------------------------------------------------------------------
# The verification gate: what CI must be able to complete, and what it
# must refuse to complete without
# ---------------------------------------------------------------------


def _ci_job():
    """Returns the verification gate as one view over the workflow's jobs.

    The gate is delivered as several jobs rather than one, so that a
    failing check in one cannot stop another's checks from running -- a
    frontend failure, in particular, must not skip the security gates.
    :data:`CI_JOB` is the job the gate's own checks live in; the
    integration, frontend and infrastructure jobs carry the rest.

    Every claim in this section is about what the gate performs, not about
    which job performs it, so the jobs are read as a single view: steps in
    workflow order, and services and environment merged with the gate job's
    own values kept where two jobs name the same key. Ordering claims are
    unaffected because the steps they compare sit in the same job.
    """
    document = _workflow_document(CI_WORKFLOW)
    jobs = document["jobs"]
    ordered = [jobs[CI_JOB]] + [
        job for name, job in jobs.items() if name != CI_JOB
    ]
    merged = {"steps": [], "services": {}, "env": {}}
    for job in ordered:
        merged["steps"].extend(job.get("steps") or [])
        for key in ("services", "env"):
            for name, value in (job.get(key) or {}).items():
                merged[key].setdefault(name, value)
    return merged


def _ci_step_names():
    """Returns the name, or the action, of every step in order."""
    return [
        step.get("name") or step.get("uses")
        for step in _ci_job()["steps"]
    ]


def _declared_npm_scripts():
    """Returns the script names the frontend manifest declares."""
    import json

    manifest = json.loads(
        FRONTEND_MANIFEST.read_text(encoding="utf-8")
    )
    return set(manifest.get("scripts", {}))


def test_the_workflow_invokes_no_npm_script_that_is_not_declared():
    """Every ``npm run`` names a script the manifest declares.

    The frontend manifest is read-only, so a gate invoking a script it
    does not declare can never pass -- and because it sat ahead of the
    backend gates, none of those was reachable on a clean checkout. This
    is the assertion that keeps such a step from returning.
    """
    declared = _declared_npm_scripts()
    invoked = NPM_SCRIPT_CALL.findall(
        CI_WORKFLOW.read_text(encoding="utf-8")
    )

    assert set(invoked) <= declared, (sorted(invoked), sorted(declared))


def test_the_workflow_runs_no_frontend_test_suite():
    """No frontend suite can fail the gate for having no tests.

    ``frontend/src`` carries no test file and is read-only, so a step
    running its suite unconditionally fails on a clean checkout. A step
    that runs it is therefore required to say so, which is what
    ``--passWithNoTests`` does: it reports the empty workspace honestly and
    still fails once a test is added and does not pass. The scope decision
    is recorded in docs/security/DECISION_LOG.md.
    """
    commands = _job_commands(_ci_job())

    for invocation in ("npm test", "npm run test"):
        if invocation in commands:
            assert "--passWithNoTests" in commands, invocation


def test_the_workflow_still_installs_the_frontend_lockfile():
    """Lockfile integrity is checkable, so it is still checked."""
    assert "npm ci" in _job_commands(_ci_job())


def test_the_node_major_supports_the_committed_lockfile():
    """The Node major is one the lockfile's engine range admits."""
    setup = [
        step
        for step in _ci_job()["steps"]
        if str(step.get("uses", "")).startswith("actions/setup-node")
    ]

    assert len(setup) == 1
    declared = str(setup[0]["with"]["node-version"])
    assert int(declared.split(".")[0]) >= MIN_SUPPORTED_NODE_MAJOR, (
        declared
    )


def test_the_lockfile_still_declares_the_engine_range_relied_on():
    """The authority for that floor is the lockfile, and it is read."""
    text = FRONTEND_LOCKFILE.read_text(encoding="utf-8")

    assert '"lockfileVersion": 3' in text
    assert '">=%d"' % MIN_SUPPORTED_NODE_MAJOR in text


def test_the_verification_gate_defers_no_work_to_a_person():
    """No step is a placeholder waiting to be written.

    The integration step was such a placeholder: a comment asking for
    commands, which succeeds without running anything, so the workflow
    reported a passing integration gate it did not have.
    """
    text = CI_WORKFLOW.read_text(encoding="utf-8")

    for marker in DEFERRED_WORK_MARKERS:
        assert marker not in text, marker


def test_every_step_of_the_gate_carries_a_command_or_an_action():
    """No step is empty, so none can pass without doing anything."""
    for step in _ci_job()["steps"]:
        body = step.get("run") or step.get("uses")
        assert body, step
        assert body.strip(), step


def test_the_gate_provisions_the_database_major_it_is_deployed_on():
    """The service pins the major Compose and Terraform both pin."""
    services = _ci_job()["services"]

    assert CI_DATABASE_SERVICE in services
    image = services[CI_DATABASE_SERVICE]["image"]
    assert image.startswith(CI_DATABASE_IMAGE_MAJOR), image
    assert "5432:5432" in [
        str(entry) for entry in services[CI_DATABASE_SERVICE]["ports"]
    ]


def test_the_gate_names_the_server_the_dialect_cases_read():
    """The fixtures' own variable is exported, and points at the service."""
    environment = _ci_job()["env"]

    assert POSTGRES_URL_VARIABLE in environment
    url = environment[POSTGRES_URL_VARIABLE]
    assert url.startswith("postgresql://")
    assert ":5432/" in url


def test_the_gate_refuses_to_skip_the_dialect_cases():
    """The cases fail rather than skip when no server is reachable.

    Without this, a runner that lost its database would report a passing
    job over a suite of skips -- which is the shape of the gap H-06
    named, where the dialect was never exercised at all.
    """
    environment = _ci_job()["env"]

    assert str(environment[POSTGRES_REQUIRED_VARIABLE]) == "1"


def test_the_gate_runs_the_marked_dialect_cases():
    """A step selects the marker, so those cases are reached."""
    commands = _job_commands(_ci_job())

    assert "-m %s" % POSTGRES_MARKER in commands


def test_the_marker_is_declared_so_it_cannot_be_misspelled():
    """The marker is registered, so a typo is reported not ignored."""
    text = (REPO_ROOT / "setup.cfg").read_text(encoding="utf-8")

    assert "%s:" % POSTGRES_MARKER in text


def test_the_gate_applies_and_reverses_the_migrations():
    """Both revisions are applied, reversed and applied again.

    Reversibility is a stated requirement of the schema change, and this
    is where it is exercised: two downgrades take the database below both
    revisions, and the upgrade that follows proves they re-apply.
    """
    commands = _job_commands(_ci_job())

    assert "%s upgrade head" % MIGRATION_COMMAND in commands
    assert commands.count("%s downgrade -1" % MIGRATION_COMMAND) == 2


def test_the_gate_counts_the_administrators_after_migrating():
    """Exactly one administrator is asserted, in the pipeline."""
    commands = _job_commands(_ci_job())

    assert "role = 'admin'" in commands
    assert "administrators == 1" in commands


def test_the_administrator_count_runs_after_the_migrations():
    """The count is meaningless before the revisions have applied."""
    job = _ci_job()

    assert _step_index(job, "upgrade head") < _step_index(
        job, "administrators == 1"
    )


def test_the_gate_checks_that_the_application_starts():
    """The import gate is a stated success criterion, so it is run."""
    assert "import backend.app.main" in _job_commands(_ci_job())


def test_the_gate_carries_the_secret_and_ignore_policy_check():
    """The recurrence gate exists and is invoked by the workflow."""
    assert SECRET_POLICY_SCRIPT.is_file()
    assert SECRET_POLICY_INVOCATION in _job_commands(_ci_job())


def test_the_secret_policy_check_stops_at_its_first_failure():
    """It runs under strict shell options, so no check is skipped."""
    text = SECRET_POLICY_SCRIPT.read_text(encoding="utf-8")

    assert "set -Eeuo pipefail" in text


def test_the_secret_policy_check_covers_all_four_properties():
    """It scans tracked paths, tracked content and the ignore rules."""
    text = SECRET_POLICY_SCRIPT.read_text(encoding="utf-8")

    assert "git ls-files" in text
    assert "git grep" in text
    assert "git check-ignore" in text
    assert "REINTRODUCTION_PATHS" in text
    assert "REQUIRED_PATHS" in text


@pytest.mark.parametrize("advisory", RUNTIME_ADVISORIES)
def test_each_runtime_advisory_is_recorded_where_the_gate_says(advisory):
    """The runtime register points at the residual-risk document.

    The workflow suppresses fourteen advisories across two manifests, and
    only these seven are recorded in that document. The comment above each
    suppression names the right authority for its own set, so a reader
    following it finds the entry rather than an absence.
    """
    assert advisory in CI_WORKFLOW.read_text(encoding="utf-8")
    assert advisory in RESIDUAL_RISK_REGISTER.read_text(encoding="utf-8")


@pytest.mark.parametrize("advisory", DEVELOPMENT_ADVISORIES)
def test_each_development_advisory_is_recorded_in_its_manifest(advisory):
    """The development register points at the manifest that declares it."""
    assert advisory in CI_WORKFLOW.read_text(encoding="utf-8")
    assert advisory in DEVELOPMENT_MANIFEST.read_text(encoding="utf-8")


def test_the_two_advisory_registers_are_suppressed_separately():
    """Each manifest is audited by its own step, under its own comment.

    One step suppressing all fourteen identifiers would point a reader at
    a single authority that documents only half of them.
    """
    steps = _ci_job()["steps"]
    audits = [
        step
        for step in steps
        if "pip-audit" in (step.get("run") or "")
    ]

    assert len(audits) == 2
    runtime = [
        step
        for step in audits
        if "requirements.txt" in step["run"]
        and "requirements-dev.txt" not in step["run"]
    ]
    development = [
        step for step in audits if "requirements-dev.txt" in step["run"]
    ]
    assert len(runtime) == 1
    assert len(development) == 1
    for advisory in RUNTIME_ADVISORIES:
        assert advisory in runtime[0]["run"], advisory
        assert advisory not in development[0]["run"], advisory
    for advisory in DEVELOPMENT_ADVISORIES:
        assert advisory in development[0]["run"], advisory
        assert advisory not in runtime[0]["run"], advisory
    # Each comment names the authority for its own set and only that one.
    # Pointing the development set at the residual-risk register is the
    # misdirection L-04 named: that document records the runtime seven,
    # so a reader following the reference finds seven entries missing.
    assert RESIDUAL_RISK_REGISTER.name in runtime[0]["run"]
    assert RESIDUAL_RISK_REGISTER.name not in development[0]["run"]
    assert DEVELOPMENT_MANIFEST.name in development[0]["run"]
    assert DEVELOPMENT_MANIFEST.name not in runtime[0]["run"]


def test_the_gate_reads_no_environment_file():
    """Nothing a runner happened to carry can alter a setting."""
    assert _ci_job()["env"]["ENV_FILE"] == ""


def test_the_deployment_workflow_is_gated_on_this_workflow():
    """The name CD waits for is the name this workflow declares."""
    declared = _workflow_document(CI_WORKFLOW)["name"]
    triggers = _workflow_triggers(_workflow_document(CD_WORKFLOW))

    assert declared in triggers["workflow_run"]["workflows"]


# ---------------------------------------------------------------------
# The executive presentation: the limits Rule 2 places on it, and the
# accuracy of the status it reports
# ---------------------------------------------------------------------

#: The single self-contained presentation Rule 2 requires.
DECK = REPO_ROOT / "blitzy-deck" / "executive-summary.html"

#: Rule 2's per-content-slide caps.
DECK_MAX_BODY_WORDS = 40

DECK_MAX_BULLETS = 4

#: Rule 2's bounds on the number of slides.
DECK_MIN_SECTIONS = 12

DECK_MAX_SECTIONS = 18

#: The exact versions Rule 2 requires each delivery dependency pinned to.
DECK_PINNED_DEPENDENCIES = {
    "reveal.js": "5.1.0",
    "lucide": "0.460.0",
    "mermaid": "11.4.0",
}

#: Markup that constitutes a non-text visual. Rule 2 permits no slide
#: without at least one.
DECK_VISUAL = re.compile(
    r'data-lucide|<pre class="mermaid"|class="data-table"'
    r'|class="kpi-grid"|class="icon-row"|class="accent-bar"'
)

#: A word, counted the way the deck's body limit counts one.
DECK_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9''./_-]*")


def _deck_text():
    """Returns the presentation's markup."""
    return DECK.read_text(encoding="utf-8")


def _deck_sections():
    """Returns each slide's markup, in order.

    Only the slides container is considered, so the theme above it and
    the framework configuration below it cannot be mistaken for slide
    content.
    """
    text = _deck_text()
    body = text.split('<div class="slides">', 1)[1]
    body = body.split("<!-- reveal.js framework -->", 1)[0]
    return [
        part
        for part in re.split(r"(?=<section)", body)
        if part.lstrip().startswith("<section")
    ]


def _deck_slide_kind(section):
    """Returns the slide type, defaulting to a content slide."""
    match = re.search(r'<section class="([^"]+)"', section)
    return match.group(1) if match else "content"


#: Components Rule 2 counts as a slide's non-text visual rather than as its
#: body text: the metric-card grid, the styled table and the icon row. Rule 2
#: requires every slide to carry one of these and caps body text at forty
#: words, so counting a visual's own labels as body text would set the two
#: requirements against each other -- no table-bearing slide could ever be
#: within the cap. The heading block, the brand lockup and screen-reader-only
#: text are excluded for the same reason: none of them is body prose an
#: audience reads off the slide.
VISUAL_COMPONENTS = (
    ("div", "slide-head"),
    ("div", "kpi-grid"),
    ("table", "data-table"),
    ("div", "icon-row"),
    ("div", "brand-lockup"),
    ("span", "sr-only"),
)


def _without_component(markup, tag, class_name):
    """Returns ``markup`` without each ``tag`` element carrying ``class_name``.

    Nesting is followed, so a component holding more of the same tag is
    removed whole rather than only as far as its first closing tag.
    """
    opening = re.compile(
        r'<%s\b[^>]*class="[^"]*\b%s\b[^"]*"[^>]*>' % (tag, class_name)
    )
    boundary = re.compile(r"<(/?)%s\b[^>]*>" % tag)
    while True:
        found = opening.search(markup)
        if found is None:
            return markup
        depth = 0
        for edge in boundary.finditer(markup, found.start()):
            depth += -1 if edge.group(1) else 1
            if depth == 0:
                markup = markup[: found.start()] + " " + markup[edge.end():]
                break
        else:
            return markup[: found.start()] + " "


def _without_visual_components(markup):
    """Returns ``markup`` without every declared visual component."""
    for tag, class_name in VISUAL_COMPONENTS:
        markup = _without_component(markup, tag, class_name)
    return markup


def _deck_body_words(section):
    """Returns the words a slide's body carries.

    The heading is excluded because Rule 2 caps the body text rather
    than the title, a diagram's source is excluded because it renders
    as a picture rather than as prose, the speaker notes are excluded
    because they are never shown to the audience, and each declared
    visual component is excluded because it is the slide's visual rather
    than its body.
    """
    without_diagram = re.sub(
        r'<pre class="mermaid">.*?</pre>', " ", section, flags=re.S
    )
    without_notes = re.sub(
        r'<aside class="notes">.*?</aside>', " ", without_diagram, flags=re.S
    )
    without_visuals = _without_visual_components(without_notes)
    without_heading = re.sub(
        r"<h[1-4][^>]*>.*?</h[1-4]>", " ", without_visuals, flags=re.S
    )
    stripped = re.sub(r"<[^>]+>", " ", without_heading)
    return DECK_WORD.findall(html.unescape(stripped))


def test_the_deck_carries_a_permitted_number_of_slides():
    """Rule 2 bounds the presentation at twelve to eighteen slides."""
    sections = _deck_sections()

    assert DECK_MIN_SECTIONS <= len(sections) <= DECK_MAX_SECTIONS, len(
        sections
    )


def test_every_content_slide_is_within_the_body_word_limit():
    """No content slide carries more body text than Rule 2 permits.

    The limit is what keeps the presentation readable by the audience it
    is written for, so it is asserted per slide and reported per slide
    rather than as an aggregate that a single dense slide could hide in.
    """
    over = {}
    for number, section in enumerate(_deck_sections(), 1):
        if _deck_slide_kind(section) != "content":
            continue
        count = len(_deck_body_words(section))
        if count > DECK_MAX_BODY_WORDS:
            over[number] = count

    assert not over, over


def test_every_slide_is_within_the_bullet_limit():
    """No slide carries more bullets than Rule 2 permits."""
    over = {}
    for number, section in enumerate(_deck_sections(), 1):
        count = len(re.findall(r"<li>", section))
        if count > DECK_MAX_BULLETS:
            over[number] = count

    assert not over, over


def test_every_slide_carries_a_non_text_visual():
    """Rule 2 permits no text-only slide."""
    missing = [
        number
        for number, section in enumerate(_deck_sections(), 1)
        if not DECK_VISUAL.search(section)
    ]

    assert not missing, missing


def test_the_deck_uses_only_the_permitted_slide_types():
    """Each slide is a title, divider, content or closing slide."""
    kinds = [_deck_slide_kind(s) for s in _deck_sections()]

    assert set(kinds) <= {
        "slide-title",
        "slide-divider",
        "slide-closing",
        "content",
    }, sorted(set(kinds))
    assert kinds.count("slide-title") == 1
    assert kinds.count("slide-closing") == 1


def test_the_deck_carries_no_emoji_and_no_foreign_iconography():
    """Lucide is the only iconography, and no emoji appears."""
    text = _deck_text()
    emoji = [
        character
        for character in text
        if ord(character) > 0x2100
        and not 0x2010 <= ord(character) <= 0x2E7F
    ]

    assert not emoji, repr(emoji[:8])
    assert not re.findall(
        r"font-awesome|material-icons|<svg", text
    )
    assert "data-lucide" in text


def test_the_deck_pins_every_delivery_dependency():
    """Each dependency resolves to the exact version Rule 2 names."""
    text = _deck_text()

    for dependency, version in DECK_PINNED_DEPENDENCIES.items():
        found = set(
            re.findall(
                r"cdn\.jsdelivr\.net/npm/%s@([0-9.]+)"
                % re.escape(dependency),
                text,
            )
        )
        assert found == {version}, (dependency, found)


def test_the_deck_needs_no_build_step_and_no_local_asset():
    """A single file opens on its own, with the theme inline."""
    text = _deck_text()
    local = re.findall(
        r'(?:src|href)="(?!https://|data:)([^"#][^"]*)"', text
    )

    assert not local, local
    assert "<style" in text
    assert "--blitzy-primary" in text


def test_the_deck_renders_its_diagrams_after_the_framework_is_ready():
    """Diagrams initialise deferred and re-run on every slide change.

    A diagram that only renders once leaves later slides blank, so both
    the ready hook and the slide-change hook are asserted rather than
    just the presence of a diagram library.
    """
    text = _deck_text()

    assert re.search(r"startOnLoad\s*:\s*false", text)
    assert re.search(r"(?:'|\")ready(?:'|\")", text)
    assert re.search(r"(?:'|\")slidechanged(?:'|\")", text)
    assert "Reveal.initialize" in text


def test_the_deck_reports_the_status_the_matrix_records():
    """The deck's headline status matches the tallied finding statuses.

    The deck is written for readers who will not open the traceability
    matrix, so an overstatement here is the version of the outcome that
    reaches decision-makers. Both numbers are asserted against the
    matrix's own rows, and the claim that every finding is closed is
    asserted absent, because five of them are not.
    """
    text = _deck_text()
    tallied = _tallied_statuses()
    prose = " ".join(re.sub(r"<[^>]+>", " ", text).split())

    assert str(tallied["PASS"]) in prose or "Fifteen" in prose
    assert str(tallied["PARTIAL"]) in prose or "five" in prose.lower()

    # The outstanding operational step is named rather than absorbed.
    assert "operational" in prose.lower()
    assert "rotat" in prose.lower()

    # No claim that the whole set is closed.
    for overstatement in (
        "all 20 findings closed",
        "all twenty findings closed",
        "twenty security findings closed",
        "every finding closed",
    ):
        assert overstatement not in prose.lower(), overstatement


def test_the_record_threshold_is_published_and_documented():
    """The deployment can set the level the records are filtered at.

    Without a published threshold every deployment records at the one
    level compiled into the application, so an incident cannot be
    investigated at a lower level and a noisy namespace cannot be raised.
    """
    entries = dict(_environment_entries(BACKEND_SERVICE))

    assert LOG_LEVEL_SETTING in entries
    assert entries[LOG_LEVEL_SETTING] == "${LOG_LEVEL:-INFO}"
    assert LOG_LEVEL_SETTING in _documented_variables()
    assert LOG_LEVEL_SETTING in _settings_fields()


def test_the_published_threshold_default_is_a_level_the_code_accepts():
    """The compose default and the code default name the same level."""
    entries = dict(_environment_entries(BACKEND_SERVICE))
    published = entries[LOG_LEVEL_SETTING].split(":-")[-1].rstrip("}")

    assert published in LOG_LEVEL_NAMES
    assert published == Settings.__fields__[LOG_LEVEL_SETTING].default


@pytest.mark.parametrize("name", RETIRED_SETTINGS)
def test_a_retired_setting_is_published_nowhere(name):
    """A setting nothing reads is declared, published and documented
    nowhere.

    A published setting is a statement that the deployment can act on it.
    One the application never reads is a false statement: an operator who
    sets it believes a control is active that is not.
    """
    assert name not in _settings_fields()
    assert name not in dict(_environment_entries(BACKEND_SERVICE))
    assert name not in _documented_variables()
    assert name not in _compose_text()


@pytest.mark.parametrize("name", RETIRED_SETTINGS)
def test_a_retired_setting_is_named_in_no_source_file(name):
    """No module, manifest or example file still names it."""
    for path in (
        REPO_ROOT / "backend" / "app" / "core" / "config.py",
        REPO_ROOT / "backend" / "requirements.txt",
        ENVIRONMENT_EXAMPLE,
    ):
        assert name not in path.read_text(encoding="utf-8"), str(path)
