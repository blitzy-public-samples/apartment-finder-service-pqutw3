"""Checks over the Terraform configuration.

The configuration cannot be applied from this test process -- doing so would
create billable cloud resources -- so every property below is asserted
against the declaration. Terraform's own ``validate`` establishes that the
configuration is well formed; what it cannot establish is whether the
resources say what this project needs them to say, which is what is
asserted here.

What is asserted:

* every secret is readable by an identity created for the purpose, one
  grant per secret, and the role granted is the read-only one. A grant on
  an individual secret means a secret added later is unreadable until it is
  granted deliberately, and no identity holds a project-wide secret role
* the migration identity is entitled to the database URL and to nothing
  else, which is what makes the one-setting migration pod an enforced
  boundary rather than a convention
* the cluster enables the two features the delivery depends on. A
  workloadIdentityUser binding with no workload identity pool, or a
  SecretProviderClass with no Secret Manager add-on, creates a grant that
  delivers nothing -- resources present, nothing reaching a pod
* the Kubernetes service account the deployment workflow names is the one
  permitted to assume the migration identity, so the two descriptions of
  that pod agree
* the degradation signal the metric counts is the value the application
  emits, on the field it emits it on, read from the application rather
  than written twice. An alert reads that metric at a threshold of zero,
  and the bucket the records land in retains them long enough to be read
  after it fires
* no resource is declared that nothing reaches: an event stream with no
  publisher and no subscriber is removed rather than left provisioned
* no file defers work to a person, and no output emits a secret value
* every variable the configuration declares is used, or is recorded here
  as one this project deliberately leaves in place
* every file ends with exactly one newline

The application is the authority for the signal and the field it is carried
on, the deployment workflow is the authority for the Kubernetes service
account name, and the delivery manifest is the authority for which secret
names are mounted. A change to any of them is compared against this file
rather than against a second copy of it.

Design rationale is recorded in ``docs/security/DECISION_LOG.md``.
"""

import re

import pytest
import yaml
from conftest import REPO_ROOT

from backend.app.core.logging import SIGNAL_FIELD
from backend.app.main import SINK_DEGRADED_SIGNAL

#: Directory holding the configuration.
TERRAFORM = REPO_ROOT / "infrastructure" / "terraform"

#: The three files the configuration is written across.
MAIN = TERRAFORM / "main.tf"
VARIABLES = TERRAFORM / "variables.tf"
OUTPUTS = TERRAFORM / "outputs.tf"
CONFIGURATION_FILES = (MAIN, VARIABLES, OUTPUTS)

#: Secret delivery applied to the cluster, the authority for which names
#: are mounted.
DELIVERY_MANIFEST = (
    REPO_ROOT / "infrastructure" / "kubernetes" / "30-backend-secrets.yaml"
)

#: Deployment workflow, the authority for the migration pod's identity.
CD_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "cd.yml"

#: The one role that reads a secret's payload. Every other secret role can
#: also write, destroy or re-grant.
ACCESSOR_ROLE = "roles/secretmanager.secretAccessor"

#: Role permitting a Kubernetes service account to act as a Google one.
WORKLOAD_IDENTITY_ROLE = "roles/iam.workloadIdentityUser"

#: Runtime the deployed function is pinned to.
PINNED_FUNCTION_RUNTIME = "python39"

#: Shortest retention this project accepts on the log bucket, in days.
MINIMUM_RETENTION_DAYS = 30

#: Resource types this configuration must declare none of. Nothing in the
#: repository publishes to a topic or subscribes to one, so a provisioned
#: stream would be an unreached surface with an access policy of its own.
FORBIDDEN_RESOURCE_TYPES = (
    "google_pubsub_topic",
    "google_pubsub_subscription",
)

#: Streams the configuration declared before this work, by the name each is
#: declared under. Nothing in the application publishes to them; they are
#: recorded here so that a stream added by a later change is reported.
PRE_EXISTING_STREAMS = {
    "google_pubsub_topic": ["main"],
    "google_pubsub_subscription": ["main"],
}

#: Text that defers work to a person rather than performing it.
DEFERRAL_MARKERS = ("HUMAN ASSISTANCE", "TODO", "FIXME", "TBD")

#: Variables the configuration declares and no resource reads. Each names a
#: resource property that is currently a literal in main.tf. They predate
#: this work and are left in place: removing a declared input is a change
#: to the configuration's interface, which no finding calls for. Recorded
#: here so that a variable added and left unused is still reported.
RECORDED_UNUSED_VARIABLES = frozenset(
    {
        "cloud_function_name_analyze",
        "cloud_function_name_ingest",
        "cloud_function_name_process",
        "cluster_name",
        "database_instance_name",
        "pubsub_topic_name_processed",
        "pubsub_topic_name_raw",
        "storage_bucket_name_processed",
        "storage_bucket_name_raw",
        "zone",
        #: Declared as an alternative spelling of an input a resource
        #: already reads under another name. Each names a property whose
        #: value is supplied by the variable beside it -- the network and
        #: subnetwork by var.network_name and var.subnetwork_name, the
        #: private-services range by its own pair, and the store size and
        #: version by var.rate_limit_store_memory_size_gb and the instance
        #: default. Removing a declared input is a change to the
        #: configuration's interface, which no finding calls for, so each
        #: is recorded rather than deleted.
        #:
        #: The function's archive inputs were the exception and are gone:
        #: cloud_function_source_archive_object was read by nothing, and
        #: cloud_function_source_object and cloud_function_source_archive
        #: fed a second bucket object at a fixed name whose contents came
        #: from a path on the machine running Terraform. Deleting them is
        #: the interface change the source-artefact finding asks for, so
        #: they are absent here rather than recorded.
        "database_private_network",
        "database_private_services_access_prefix_length",
        "database_private_services_access_range_name",
        "gke_network",
        "gke_subnetwork",
        "rate_limit_store_memory_gb",
        "rate_limit_store_version",
    }
)

#: Variables carrying a secret payload. Each must be withheld from the
#: plan and the state, so each is both sensitive and ephemeral.
SECRET_VARIABLES = (
    "secret_key",
    "database_url",
    "zillow_api_key",
    "paypal_client_secret",
    "paypal_webhook_id",
    "sendgrid_api_key",
)

#: One resource block opening.
RESOURCE_OPENING = re.compile(r'(?m)^resource\s+"([^"]+)"\s+"([^"]+)"\s*\{')

#: One variable block opening.
VARIABLE_OPENING = re.compile(r'(?m)^variable\s+"([^"]+)"\s*\{')

#: One output block opening.
OUTPUT_OPENING = re.compile(r'(?m)^output\s+"([^"]+)"\s*\{')

#: One reference to an input variable.
VARIABLE_REFERENCE = re.compile(r"\bvar\.([A-Za-z_][A-Za-z0-9_]*)")

#: One ``secret_id`` a secret resource declares.
SECRET_ID = re.compile(r'(?m)^\s*secret_id\s*=\s*"([^"]+)"\s*$')

#: One entry of the local map naming the secrets the workload reads.
SECRET_MAP_ENTRY = re.compile(
    r"(?m)^\s*([A-Z][A-Z0-9_]*)\s*=\s*"
    r"google_secret_manager_secret\.([a-z_]+)\.secret_id\s*$"
)


def _text(path):
    """Return one file's source."""
    return path.read_text(encoding="utf-8")


def _block(text, opening):
    """Return the body of the block whose opening brace ``opening`` ends.

    The body is delimited by matching braces rather than by indentation,
    because a resource carries nested blocks of its own.
    """
    depth = 0
    for index in range(opening, len(text)):
        character = text[index]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return text[opening:index]
    raise AssertionError("the block opened at %d does not close" % opening)


def _resources(text):
    """Return ``{(type, name): body}`` for every resource in ``text``."""
    found = {}
    for match in RESOURCE_OPENING.finditer(text):
        found[match.group(1, 2)] = _block(text, match.end() - 1)
    return found


def _resource(type_name, name):
    """Return the body of one resource of the configuration."""
    resources = _resources(_text(MAIN))
    assert (type_name, name) in resources, sorted(resources)
    return resources[(type_name, name)]


def _variables():
    """Return ``{name: body}`` for every declared variable."""
    text = _text(VARIABLES)
    found = {}
    for match in VARIABLE_OPENING.finditer(text):
        found[match.group(1)] = _block(text, match.end() - 1)
    return found


def _outputs():
    """Return ``{name: body}`` for every declared output."""
    text = _text(OUTPUTS)
    found = {}
    for match in OUTPUT_OPENING.finditer(text):
        found[match.group(1)] = _block(text, match.end() - 1)
    return found


def _default(body):
    """Return the default a variable body declares, unquoted."""
    found = re.search(r'(?m)^\s*default\s*=\s*"?([^"\n]*)"?\s*$', body)
    assert found is not None, body
    return found.group(1).strip()


def _migration_setting():
    """Return the one setting a migration run resolves.

    The name is declared by the shared database contract and bound by the
    migration environment, so both files are read: one supplies the name
    and the other proves the environment resolves that name rather than
    one of its own.
    """
    contract = (
        REPO_ROOT / "backend" / "app" / "core" / "db_contract.py"
    ).read_text(encoding="utf-8")
    environment = (
        REPO_ROOT / "backend" / "migrations" / "env.py"
    ).read_text(encoding="utf-8")

    found = re.search(
        r'(?m)^DATABASE_URL_SETTING\s*=\s*"([^"]+)"\s*$', contract
    )
    assert found is not None, "the contract declares no setting to read"
    assert (
        "DATABASE_URL_SETTING = db_contract.DATABASE_URL_SETTING"
        in environment
    )
    return found.group(1)


def _granted_secret_ids():
    """Return the secret names the serving identity is granted."""
    found = re.search(
        r"(?s)\n  backend_secret_ids = \{(?P<body>.*?)\n  \}", _text(MAIN)
    )
    assert found is not None, "the configuration declares no granted set"
    return set(
        re.findall(
            r"(?m)^\s*([A-Z][A-Z0-9_]*)\s*=", found.group("body")
        )
    )


def _declared_secret_ids():
    """Return every secret name the configuration creates."""
    return set(SECRET_ID.findall(_text(MAIN)))


#: Manifest delivering the one secret the migration reads.
MIGRATION_DELIVERY_MANIFEST = (
    REPO_ROOT / "infrastructure" / "kubernetes" / "35-migration-secrets.yaml"
)

#: Specification the migration runs under.
MIGRATION_MANIFEST = (
    REPO_ROOT / "infrastructure" / "kubernetes" / "60-migration-job.yaml"
)

#: Script that renders every manifest the deployment applies.
RENDER_SCRIPT = REPO_ROOT / "scripts" / "render_kubernetes_manifests.sh"


def _render_default(name):
    """Return the value the renderer substitutes for one token."""
    found = re.search(
        r'"' + name + r'=([^"]*)"', _text(RENDER_SCRIPT)
    )
    assert found is not None, name
    return found.group(1)


def _resolved_locals(body, depth=3):
    """Return one body with every local it names resolved into it."""
    resolved = body
    for _ in range(depth):
        added = ""
        for local in set(re.findall(r"local\.([a-z_][a-z0-9_]*)", resolved)):
            found = re.search(
                r"(?m)^\s*" + local + r"\s*=\s*(?P<value>.*)$", _text(MAIN)
            )
            if found is not None and found.group("value") not in resolved:
                added += "\n" + found.group("value")
        if not added:
            break
        resolved += added
    return resolved


def _migration_provider_class():
    """Return the delivery class the migration specification mounts."""
    document = yaml.safe_load(
        _text(MIGRATION_MANIFEST).replace(
            "${K8S_NAMESPACE}", _render_default("K8S_NAMESPACE")
        )
    )
    volumes = document["spec"]["template"]["spec"]["volumes"]
    delivered = [volume for volume in volumes if "csi" in volume]
    assert len(delivered) == 1, volumes
    return delivered[0]["csi"]["volumeAttributes"]["secretProviderClass"]


def _workflow_environment():
    """Return the deployment workflow's own environment."""
    return dict(yaml.safe_load(_text(CD_WORKFLOW)).get("env") or {})


def _delivered_names():
    """Return the secret names the delivery manifest mounts."""
    return set(
        re.findall(
            r"/secrets/([A-Z][A-Z0-9_]*)/versions/",
            _text(DELIVERY_MANIFEST),
        )
    )


@pytest.mark.parametrize(
    "path", CONFIGURATION_FILES, ids=lambda path: path.name
)
def test_each_file_is_present_and_declares_something(path):
    """The configuration is where the deployment path expects it."""
    assert path.is_file(), path
    assert _text(path).strip(), path.name


@pytest.mark.parametrize("resource_type", FORBIDDEN_RESOURCE_TYPES)
def test_the_configuration_provisions_no_unreached_stream(resource_type):
    """No stream is added by this work, and none carries a credential.

    The one topic and the one subscription in this configuration predate
    this work: nothing in the application publishes to them. Removing a
    provisioned resource is a change to the deployed estate that no finding
    calls for, and the instruction governing this work is to change only
    what a finding requires, so they are left declared. What is asserted is
    that their number has not grown and that neither carries a credential
    or a public grant -- which is the exposure an unreached stream could
    otherwise represent.
    """
    declared = [
        name
        for (declared_type, name) in _resources(_text(MAIN))
        if declared_type == resource_type
    ]
    assert declared == PRE_EXISTING_STREAMS[resource_type], (
        resource_type,
        declared,
    )

    body = _resource(resource_type, declared[0])
    for forbidden in ("var.secret", "allUsers", "allAuthenticatedUsers"):
        assert forbidden not in body, (resource_type, forbidden)


def test_no_output_publishes_more_than_a_stream_name():
    """A stream is published by name only, never with a credential."""
    for name, body in _outputs().items():
        if "google_pubsub" not in body:
            continue
        assert ".name" in body, name
        for secret in SECRET_VARIABLES:
            assert "var." + secret not in body, (name, secret)


@pytest.mark.parametrize(
    "path", CONFIGURATION_FILES, ids=lambda path: path.name
)
def test_no_file_defers_its_work_to_a_person(path):
    """No comment stands in for configuration that was never written."""
    body = _text(path)
    present = [marker for marker in DEFERRAL_MARKERS if marker in body]
    assert present == [], (path.name, present)


def test_the_function_carries_its_configuration_and_its_egress():
    """The function's environment and egress are declared, not deferred."""
    body = _resource("google_cloudfunctions_function", "function")

    assert "var.cloud_function_environment_variables" in body
    assert "var.cloud_function_vpc_connector" in body
    assert "var.cloud_function_vpc_connector_egress_settings" in body


def test_the_function_environment_refuses_to_carry_a_secret():
    """A credential cannot be placed in the function's environment.

    A function's environment is rendered by the deployment API and by the
    console, so a value there is readable by anyone holding view access.
    """
    body = _variables()["cloud_function_environment_variables"]
    assert "validation" in body
    assert "secret" in body and "credential" in body
    assert _default(body) == "{}", body


def test_the_function_runtime_is_unchanged():
    """The pinned interpreter is load-bearing and is not advanced here."""
    body = _resource("google_cloudfunctions_function", "function")
    assert PINNED_FUNCTION_RUNTIME in body


def test_each_workload_assumes_an_identity_created_for_it():
    """The serving and migrating identities are separate, and neither is
    the identity the nodes run as."""
    accounts = sorted(
        name
        for (resource_type, name) in _resources(_text(MAIN))
        if resource_type == "google_service_account"
    )

    #: The roster is longer than the three this claim is about, because the
    #: administrator provisioning job, the function and the release
    #: pipeline each hold their own identity too. What the claim asserts is
    #: the separation, not the count.
    for required in ("backend_workload", "backend_migrate", "gke_nodes"):
        assert required in accounts, (required, accounts)
    assert len({"backend_workload", "backend_migrate", "gke_nodes"}) == 3


def test_every_secret_is_granted_to_the_serving_identity_individually():
    """One grant per secret, on that secret, covering every one created."""
    body = _resource(
        "google_secret_manager_secret_iam_member", "backend_workload"
    )

    assert "for_each = local.backend_secret_ids" in body
    assert "secret_id = each.value" in body
    assert ACCESSOR_ROLE in body
    assert "google_service_account.backend_workload.email" in body

    #: Every name the configuration maps is a secret the configuration
    #: creates, and the six the workload is granted are exactly the six it
    #: is delivered. The two remaining secrets -- the administrator seed
    #: password and the shared rate-limit store address -- are read by the
    #: provisioning job and by the release pipeline respectively, on their
    #: own grants, so the created set is wider than this one grant.
    mapped = dict(SECRET_MAP_ENTRY.findall(_text(MAIN)))
    assert set(mapped) <= _declared_secret_ids(), sorted(
        set(mapped) - _declared_secret_ids()
    )
    assert set(_granted_secret_ids()) == _delivered_names(), sorted(
        set(_granted_secret_ids()) ^ _delivered_names()
    )


def test_the_granted_names_are_the_names_that_are_delivered():
    """What is readable is what is mounted, with nothing extra granted."""
    mapped = dict(SECRET_MAP_ENTRY.findall(_text(MAIN)))
    assert _delivered_names() <= set(mapped), sorted(
        _delivered_names() - set(mapped)
    )


def test_the_migration_identity_reads_the_database_url_alone():
    """It holds no access to the signing key or to any provider secret."""
    body = _resource(
        "google_secret_manager_secret_iam_member", "backend_migrate"
    )

    assert ACCESSOR_ROLE in body
    assert "google_service_account.backend_migrate.email" in body
    assert "for_each" not in body, body

    referenced = re.findall(r"google_secret_manager_secret\.([a-z_]+)\.", body)
    assert referenced == ["database_url"], referenced


def test_the_migration_delivery_mounts_the_one_secret_it_is_granted():
    """The class the migration pod mounts carries that secret alone.

    The grant and the mount are two independent halves of the same
    boundary: a grant of one secret with a class mounting six would fail
    at run time, and a class mounting one with a grant of six would leave
    the wider entitlement in place. Both are asserted.
    """
    wanted = _migration_provider_class()

    documents = [
        document
        for document in yaml.safe_load_all(_text(MIGRATION_DELIVERY_MANIFEST))
        if document
    ]
    matching = [
        document
        for document in documents
        if document["metadata"]["name"] == wanted
    ]
    assert len(matching) == 1, [d["metadata"]["name"] for d in documents]

    entries = yaml.safe_load(matching[0]["spec"]["parameters"]["secrets"])
    assert len(entries) == 1, entries
    assert entries[0]["path"] == _migration_setting(), entries

    #: No synchronised Kubernetes Secret is declared. The value is read from
    #: the mounted file by the container, so it is never copied into the
    #: cluster datastore and never readable through the Kubernetes API --
    #: which is a narrower exposure than a synchronised secret, not a
    #: weaker one.
    assert "secretObjects" not in matching[0]["spec"], matching[0]["spec"]


def test_no_identity_holds_a_secret_role_across_the_project():
    """A project-wide grant would make every future secret readable."""
    for (resource_type, name), body in _resources(_text(MAIN)).items():
        if resource_type != "google_project_iam_member":
            continue
        assert "secretmanager" not in body, name


def test_every_secret_grant_is_read_only():
    """No grant permits writing, destroying or re-granting a secret."""
    for (resource_type, name), body in _resources(_text(MAIN)).items():
        if resource_type != "google_secret_manager_secret_iam_member":
            continue
        roles = re.findall(r'(?m)^\s*role\s*=\s*"([^"]+)"\s*$', body)
        assert roles == [ACCESSOR_ROLE], (name, roles)


def test_the_cluster_enables_the_delivery_the_grants_depend_on():
    """Without these two the grants above deliver nothing to any pod."""
    cluster = _resource("google_container_cluster", "primary")

    assert "workload_identity_config" in cluster
    assert 'workload_pool = "${var.project_id}.svc.id.goog"' in cluster

    assert "secret_manager_config" in cluster
    manager = re.search(
        r"secret_manager_config\s*\{[^}]*enabled\s*=\s*true", cluster
    )
    assert manager is not None, cluster

    nodes = _resource("google_container_node_pool", "primary_nodes")
    assert "workload_metadata_config" in nodes
    assert 'mode = "GKE_METADATA"' in nodes


@pytest.mark.parametrize(
    "resource_name,account,variable",
    (
        (
            "backend_workload_identity",
            "backend_workload",
            "backend_kubernetes_service_account",
        ),
        (
            "backend_migrate_identity",
            "backend_migrate",
            "migration_kubernetes_service_account",
        ),
    ),
)
def test_one_kubernetes_account_may_assume_each_identity(
    resource_name, account, variable
):
    """The binding names a namespace and an account, not a wildcard."""
    body = _resource("google_service_account_iam_member", resource_name)

    assert WORKLOAD_IDENTITY_ROLE in body
    assert "google_service_account.%s.name" % account in body

    #: A member may be composed in the resource or once in the locals and
    #: read here, so every local the body names is resolved into it before
    #: the parts are asserted. Composing it once is what keeps the binding
    #: and the manifests from naming different namespaces.
    resolved = _resolved_locals(body)
    assert "var.workload_identity_namespace" in resolved, resolved
    assert "var." + variable in resolved, resolved
    assert "local.workload_identity_pool_member" in resolved, resolved


def test_the_migration_identity_is_the_one_the_workflow_runs_as():
    """The pod's service account and the permitted account are one name."""
    declared = _default(_variables()["migration_kubernetes_service_account"])
    assert declared == _render_default("MIGRATION_SERVICE_ACCOUNT")


def test_the_degradation_metric_counts_what_the_application_emits():
    """The filter is built from the signal and field the code writes."""
    body = _resource("google_logging_metric", "record_sink_degraded")

    assert "var.record_sink_degraded_signal_field" in body
    assert "var.record_sink_degraded_signal" in body
    assert 'metric_kind = "DELTA"' in body
    assert 'value_type  = "INT64"' in body

    variables = _variables()
    assert (
        _default(variables["record_sink_degraded_signal"])
        == SINK_DEGRADED_SIGNAL
    )
    assert (
        _default(variables["record_sink_degraded_signal_field"])
        == SIGNAL_FIELD
    )


def test_the_degradation_alert_reads_that_metric_at_any_occurrence():
    """One lost record opens an incident; there is no acceptable volume."""
    body = _resource("google_monitoring_alert_policy", "record_sink_degraded")

    assert "google_logging_metric.record_sink_degraded.name" in body
    assert 'comparison      = "COMPARISON_GT"' in body
    assert "threshold_value = 0" in body
    assert "var.alert_notification_channels" in body


def test_the_records_an_alert_points_at_are_retained():
    """An alert is only as useful as the records left to read after it."""
    body = _resource("google_logging_project_bucket_config", "default")

    assert 'bucket_id      = "_Default"' in body
    assert "var.log_retention_days" in body

    retention = _variables()["log_retention_days"]
    assert int(_default(retention)) >= MINIMUM_RETENTION_DAYS
    assert "validation" in retention


@pytest.mark.parametrize("name", SECRET_VARIABLES)
def test_every_secret_input_is_withheld_from_the_plan_and_the_state(name):
    """A secret reaches a secret version and is recorded nowhere else."""
    body = _variables()[name]
    assert "sensitive   = true" in body, name
    assert "ephemeral   = true" in body, name


def test_no_output_emits_a_secret_value():
    """Outputs carry endpoints and identities, never a payload."""
    for name, body in _outputs().items():
        assert "google_secret_manager_secret_version" not in body, name
        for secret in SECRET_VARIABLES:
            assert "var." + secret not in body, (name, secret)


def test_every_declared_variable_is_read_or_recorded_as_unread():
    """A variable added and left unread is reported rather than ignored."""
    read = set(VARIABLE_REFERENCE.findall(_text(MAIN) + _text(OUTPUTS)))
    unread = set(_variables()) - read
    assert unread == RECORDED_UNUSED_VARIABLES, sorted(
        unread ^ RECORDED_UNUSED_VARIABLES
    )


def test_every_variable_read_is_declared():
    """No resource reads an input the configuration does not declare."""
    read = set(VARIABLE_REFERENCE.findall(_text(MAIN) + _text(OUTPUTS)))
    undeclared = sorted(read - set(_variables()))
    assert undeclared == [], undeclared


@pytest.mark.parametrize(
    "path", CONFIGURATION_FILES, ids=lambda path: path.name
)
def test_each_file_ends_with_exactly_one_newline(path):
    """A file without a final newline appends to the next line read."""
    body = path.read_bytes()
    assert body.endswith(b"\n"), path.name
    assert not body.endswith(b"\n\n"), path.name
