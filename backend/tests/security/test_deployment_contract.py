"""Static checks over the Compose definition that starts the service.

The container stack cannot be built or started from this test process, so
every property below is asserted against the declaration itself. What is
asserted:

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
"""

import re

import pytest
import yaml
from conftest import REPO_ROOT

from backend.app.core.config import Settings

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

#: Services the file is required to declare, in order.
EXPECTED_SERVICES = (
    "frontend",
    "backend",
    "migrate",
    "db",
    "cloud-sql-proxy",
)

#: Services that build an image from a context in this repository.
BUILD_SERVICES = ("frontend", "backend", "migrate")

#: Services that carry the backend environment anchor.
ANCHORED_SERVICES = ("backend", "migrate")

#: Profiles each service is selected by. ``db`` runs only for the local
#: profile and the proxy only for the gcp one, so exactly one of them
#: answers to the ``db`` name in any single stack.
EXPECTED_PROFILES = {
    "frontend": ["local", "gcp"],
    "backend": ["local", "gcp"],
    "migrate": ["local", "gcp"],
    "db": ["local"],
    "cloud-sql-proxy": ["gcp"],
}

#: Service running the Cloud SQL proxy under the gcp profile.
PROXY_SERVICE = "cloud-sql-proxy"

#: Variable naming the instance the proxy connects to.
PROXY_INSTANCE_VARIABLE = "CLOUD_SQL_INSTANCE_CONNECTION_NAME"

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
    "db": "pg_isready",
}

#: Executable no probe may invoke: neither ``python:3.9-slim`` nor
#: ``nginx:alpine`` installs it.
FORBIDDEN_PROBE_EXECUTABLE = "curl"

#: Build argument the frontend carries the backend's address in.
FRONTEND_TARGET_NAME = "REACT_APP_API_BASE_URL"


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
    instead, so an absent optional value never blocks a start.
    """
    required = _required_settings()
    assert required, "the settings class publishes a required field"

    for name, value in _environment_entries("backend"):
        match = SUBSTITUTION.match(value)
        operator = match.group("operator")
        if name in required:
            assert operator == REQUIRED_OPERATOR, (name, value)
            assert match.group("argument").strip(), (name, value)
        else:
            assert operator == DEFAULT_OPERATOR, (name, value)


def test_the_database_password_is_required_rather_than_defaulted():
    """Asserts the local database is never started on a known password."""
    declared = dict(_environment_entries("db"))
    value = declared["POSTGRES_PASSWORD"]

    assert SUBSTITUTION.match(value).group("operator") == REQUIRED_OPERATOR


def test_the_proxy_service_requires_its_instance_name():
    """Asserts the proxy target is substituted and reachable.

    The instance name is required rather than defaulted, and the proxy
    is declared to listen on every interface so the backend service can
    reach it across the Compose network.
    """
    command = " ".join(_service(PROXY_SERVICE)["command"])

    assert "${" + PROXY_INSTANCE_VARIABLE + ":?" in command
    assert "tcp:0.0.0.0:5432" in command


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


def test_the_backend_probe_reads_the_health_route_the_application_serves():
    """Asserts the probe addresses the served route on the served port."""
    probe = " ".join(_service("backend")["healthcheck"]["test"])
    exposed = _exposed_port(BACKEND_DOCKERFILE)

    assert "http://127.0.0.1:" + str(exposed) + "/health" in probe
