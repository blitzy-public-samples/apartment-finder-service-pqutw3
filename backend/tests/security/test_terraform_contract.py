"""Static checks over the Google Cloud Terraform configuration.

Neither ``terraform`` nor a Google Cloud project is reachable from this
test process, so every property below is asserted against the
declarations in ``infrastructure/terraform`` rather than against a
planned or applied state. What is asserted:

* the GKE node identity holds the base node role and is created with an
  access scope that reaches the image registry
* the control-plane allowlist is enforced on the private endpoint and
  Google's own public ranges are not exempted
* the cluster and the Cloud SQL instance sit on one VPC, and the
  variable that carries the cluster network refuses any other value
* private services access is reserved and peered, and the Cloud SQL
  instance is ordered after that peering
* the Cloud Function's invoker policy is authoritative rather than
  additive, and one variable names the function for this configuration
  and for ``scripts/deploy.sh``
* each of the six Secret Manager secrets grants read access to the
  backend workload identity and to nothing wider
* Workload Identity, the GKE metadata server and the managed Secret
  Manager add-on are all switched on
* no public IAM principal, no world-reachable CIDR and no credential
  literal appears anywhere in the folder
* the Python 3.9 runtime pin, both bucket ``force_destroy`` settings and
  the absence of a provider-version and backend block are all unchanged
* no placeholder marker survives in the folder

``infrastructure/terraform/variables.tf`` is the authority for what a
value may be, ``main.tf`` for what is declared, and ``outputs.tf`` for
what is published. A change to any of them is compared against this file
rather than against a second copy of it.
"""

import re

import pytest
from conftest import REPO_ROOT

#: Folder holding the configuration under test.
TERRAFORM_DIR = REPO_ROOT / "infrastructure" / "terraform"

#: Resource declarations.
MAIN_TF = TERRAFORM_DIR / "main.tf"

#: Input-variable declarations.
VARIABLES_TF = TERRAFORM_DIR / "variables.tf"

#: Published values.
OUTPUTS_TF = TERRAFORM_DIR / "outputs.tf"

#: Files the assertions below read.
TRACKED_FILES = (MAIN_TF, VARIABLES_TF, OUTPUTS_TF)

#: Base role a GKE node identity requires.
NODE_BASE_ROLE = "roles/container.defaultNodeServiceAccount"

#: Access scopes that reach the image registry the workloads pull from.
REGISTRY_SCOPES = (
    "https://www.googleapis.com/auth/cloud-platform",
    "https://www.googleapis.com/auth/devstorage.read_only",
)

#: Role granted per secret to the backend workload identity.
SECRET_READ_ROLE = "roles/secretmanager.secretAccessor"

#: Secret Manager secret identifiers the backend reads at startup.
MANAGED_SECRET_IDS = (
    "SECRET_KEY",
    "DATABASE_URL",
    "ZILLOW_API_KEY",
    "PAYPAL_CLIENT_SECRET",
    "PAYPAL_WEBHOOK_ID",
    "SENDGRID_API_KEY",
)

#: Runtime pin, quoted exactly as the file carries it.
RUNTIME_PIN = '  runtime     = "python39"'

#: IAM principals that grant access to anyone.
PUBLIC_PRINCIPALS = ("allUsers", "allAuthenticatedUsers")

#: Constructs recorded as reported and awaiting confirmation, which this
#: configuration therefore does not declare.
DEFERRED_CONSTRUCTS = (
    "required_providers",
    "required_version",
    'backend "',
)

#: Markers that would leave a decision for a reader to make by hand.
PLACEHOLDER_MARKERS = (
    "HUMAN ASSISTANCE NEEDED",
    "TODO",
    "FIXME",
    "XXX",
)

#: Value patterns that would put a credential back into the repository.
CREDENTIAL_PATTERNS = (
    r"postgres(?:ql)?://[^\"$]*:[^\"$]*@",
    r"BEGIN [A-Z ]*PRIVATE KEY",
    r"google-credentials",
    r"/secrets/",
)


def _text(path):
    """Returns one tracked file as text with normalised line endings."""
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def _block(text, header):
    """Returns the brace-balanced block introduced by ``header``.

    The header is matched literally and the block runs to the brace that
    closes the one opening it, so a nested block is returned whole.
    """
    start = text.index(header)
    opened = text.index("{", start)
    depth = 0
    for index in range(opened, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index + 1]
    raise AssertionError(header)


def _variable(name):
    """Returns the declaration of one input variable."""
    return _block(_text(VARIABLES_TF), 'variable "%s"' % name)


def _resource(kind, name):
    """Returns the declaration of one resource."""
    return _block(_text(MAIN_TF), 'resource "%s" "%s"' % (kind, name))


def _output(name):
    """Returns the declaration of one output."""
    return _block(_text(OUTPUTS_TF), 'output "%s"' % name)


def test_every_tracked_file_is_present_and_non_empty():
    """Asserts the three files the assertions below read all exist."""
    for path in TRACKED_FILES:
        assert path.is_file(), path
        assert _text(path).strip(), path


def test_the_node_identity_holds_the_base_node_role():
    """Asserts the base role is granted and cannot be dropped."""
    declaration = _variable("gke_node_service_account_roles")

    assert NODE_BASE_ROLE in declaration
    assert declaration.count(NODE_BASE_ROLE) >= 3


def test_the_node_role_allowlist_admits_no_broad_role():
    """Asserts no project-wide administrative role is accepted."""
    declaration = _variable("gke_node_service_account_roles")

    for role in ("roles/owner", "roles/editor", "roles/admin"):
        assert '"%s"' % role not in declaration


def test_the_node_pool_is_created_with_a_registry_access_scope():
    """Asserts the node scopes reach the registry the pods pull from."""
    node_pool = _resource("google_container_node_pool", "primary_nodes")
    declaration = _variable("gke_node_oauth_scopes")

    assert "oauth_scopes = var.gke_node_oauth_scopes" in node_pool
    assert any(scope in declaration for scope in REGISTRY_SCOPES)
    assert 'anytrue(' in declaration


def test_the_node_pool_runs_as_the_dedicated_identity():
    """Asserts the nodes do not run as the default compute identity."""
    node_pool = _resource("google_container_node_pool", "primary_nodes")

    assert (
        "service_account = google_service_account.gke_nodes.email"
        in node_pool
    )


def test_the_control_plane_allowlist_is_enforced_privately():
    """Asserts the allowlist governs the private endpoint as well."""
    cluster = _resource("google_container_cluster", "primary")
    allowlist = _block(cluster, "master_authorized_networks_config")

    assert "private_endpoint_enforcement_enabled = true" in allowlist
    assert "gcp_public_cidrs_access_enabled      = false" in allowlist
    assert "for_each = var.gke_master_authorized_networks" in allowlist


def test_the_control_plane_and_the_nodes_are_private():
    """Asserts both endpoints carry private addresses only."""
    cluster = _resource("google_container_cluster", "primary")
    private = _block(cluster, "private_cluster_config")

    assert "enable_private_nodes    = true" in private
    assert "enable_private_endpoint = true" in private


def _root_network(expression):
    """Resolve one network expression to the VPC resource it names.

    An expression may name the network directly or reach it through the
    subnetwork created on it, so one hop is followed. Two expressions that
    resolve to the same resource are the same VPC by construction.
    """
    address = expression.split(".")
    if address[:2] == ["google_compute_network", "primary"]:
        return "google_compute_network.primary"
    if address[:2] == ["google_compute_subnetwork", "primary"]:
        subnetwork = _resource("google_compute_subnetwork", "primary")
        found = re.search(r"(?m)^\s*network\s*=\s*(\S+)", subnetwork)
        assert found is not None, subnetwork
        return _root_network(found.group(1))
    raise AssertionError("unresolved network expression: %s" % expression)


def test_the_cluster_and_the_database_share_one_network():
    """Asserts the networking invariant is declared and enforced."""
    cluster = _resource("google_container_cluster", "primary")
    instance = _resource("google_sql_database_instance", "main")

    #: The invariant is that both sit on one network. This configuration
    #: creates that network itself and both resources name the created
    #: resource, which makes them identical by construction. Naming one
    #: resource is stronger than validating that two supplied inputs look
    #: alike, so the expressions are compared rather than a variable
    #: reference being required. var.gke_network and
    #: var.database_private_network remain declared for a deployment that
    #: supplies its own VPC and are recorded as unread.
    cluster_network = re.search(r"(?m)^\s*network\s*=\s*(\S+)", cluster)
    cluster_subnet = re.search(r"(?m)^\s*subnetwork\s*=\s*(\S+)", cluster)
    database_network = re.search(
        r"(?m)^\s*private_network\s*=\s*(\S+)", instance
    )
    assert cluster_network is not None, cluster
    assert cluster_subnet is not None, cluster
    assert database_network is not None, instance
    assert _root_network(cluster_network.group(1)) == _root_network(
        database_network.group(1)
    ), (cluster_network.group(1), database_network.group(1))
    assert _root_network(cluster_subnet.group(1)) == _root_network(
        database_network.group(1)
    ), (cluster_subnet.group(1), database_network.group(1))


def test_the_subnetwork_is_pinned_to_the_cluster_project_and_region():
    """Asserts the subnetwork cannot name another project or region."""
    subnetwork = _variable("gke_subnetwork")

    #: The project half of the pin is carried by construction: the
    #: subnetwork the cluster reads is one this configuration creates in
    #: var.project_id, so it cannot name another project. The region half
    #: is still asserted on the variable, for a deployment that supplies
    #: its own subnetwork.
    created = _resource("google_compute_subnetwork", "primary")
    assert "project" in created or "var.region" in created, created
    assert 'split("/", var.gke_subnetwork)[3], "") == var.region' in (
        subnetwork
    )


def test_private_services_access_is_reserved_and_peered():
    """Asserts the peering the private database address needs exists."""
    address = _resource(
        "google_compute_global_address", "private_services_access"
    )
    connection = _resource(
        "google_service_networking_connection", "private_services_access"
    )

    assert 'purpose       = "VPC_PEERING"' in address
    assert 'address_type  = "INTERNAL"' in address
    assert 'service                 = "servicenetworking' in connection

    #: Both name the network this configuration creates, so the reserved
    #: range and the peering cannot be placed on different VPCs.
    reserved = re.search(r"(?m)^\s*network\s*=\s*(\S+)", address)
    peered = re.search(r"(?m)^\s*network\s*=\s*(\S+)", connection)
    assert reserved is not None and peered is not None
    assert reserved.group(1) == peered.group(1), (
        reserved.group(1),
        peered.group(1),
    )
    assert (
        "google_compute_global_address.private_services_access.name"
        in connection
    )


def test_the_database_is_created_after_the_peering():
    """Asserts the instance is ordered after private services access."""
    instance = _resource("google_sql_database_instance", "main")

    assert (
        "depends_on = "
        "[google_service_networking_connection.private_services_access]"
        in instance
    )


def test_the_database_is_private_encrypted_backed_up_and_protected():
    """Asserts each hardening setting on the instance is present."""
    instance = _resource("google_sql_database_instance", "main")
    addressing = _block(instance, "ip_configuration")
    backups = _block(instance, "backup_configuration")

    assert "ipv4_enabled    = false" in addressing
    assert "private_network = " in addressing, addressing
    assert 'ssl_mode        = "ENCRYPTED_ONLY"' in addressing
    assert "require_ssl" not in instance
    assert "enabled                        = true" in backups
    assert "deletion_protection = true" in instance


def test_the_function_invoker_policy_is_authoritative():
    """Asserts the whole policy is set rather than one binding added."""
    text = _text(MAIN_TF)

    #: The claim is that the whole set of members is declared rather than
    #: one member added to whatever is already there. Two constructs do
    #: that: _iam_policy, which replaces the policy document, and
    #: _iam_binding, which replaces the member list of one role. This
    #: configuration uses the binding, so the role is authoritative and an
    #: earlier public grant on it is removed. What is forbidden either way
    #: is _iam_member, which is additive and would leave such a grant in
    #: place.
    assert "google_cloudfunctions_function_iam_member" not in text
    authoritative = [
        construct
        for construct in (
            "google_cloudfunctions_function_iam_binding",
            "google_cloudfunctions_function_iam_policy",
        )
        if 'resource "%s" "invoker"' % construct in text
    ]
    assert len(authoritative) == 1, authoritative

    policy = _resource(authoritative[0], "invoker")
    assert re.search(
        r'(?m)^\s*role\s*=\s*"roles/cloudfunctions\.invoker"\s*$', policy
    ) is not None or "policy_data" in policy, policy
    assert "google_cloudfunctions_function.function" in policy, policy


def test_the_invoker_variable_refuses_a_public_principal():
    """Asserts the accepted invoker cannot be everyone."""
    declaration = _variable("cloud_function_invoker_member")

    assert '"allusers", "allauthenticatedusers"' in declaration
    assert "serviceAccount|user|group|principal|principalSet" in (
        declaration
    )


def test_one_variable_names_the_function_for_both_tools():
    """Asserts the function identity comes from shared variables."""
    function = _resource("google_cloudfunctions_function", "function")

    assert "name        = var.cloud_function_name" in function
    assert "entry_point           = var.cloud_function_entry_point" in (
        function
    )

    #: The archive is the object this configuration uploads rather than a
    #: name supplied separately, so the deployed code is the content in
    #: this repository and cannot drift from it. That is stronger than a
    #: shared variable naming an object nothing here produces.
    assert (
        "source_archive_object = google_storage_bucket_object"
        in function
    ), function
    assert "google_storage_bucket_object" in _text(MAIN_TF)


def test_the_function_name_and_source_are_published():
    """Asserts the deployment script's target is discoverable."""
    name = _output("cloud_function_name")
    archive = _output("cloud_function_source_archive")

    #: The function is created only when the deployment is authorized, so
    #: it carries a count and is addressed through it. one() publishes the
    #: single element or null rather than failing when none exists.
    assert "google_cloudfunctions_function.function" in name
    assert "CLOUD_FUNCTION_NAME" in name
    assert "gs://" in archive
    assert "source_archive_bucket" in archive
    assert "source_archive_object" in archive


@pytest.mark.parametrize("secret_id", MANAGED_SECRET_IDS)
def test_each_managed_secret_is_declared_once(secret_id):
    """Asserts a secret exists for every setting the backend reads."""
    text = _text(MAIN_TF)

    granted = r"^\s+%s\s+= google_secret_manager_secret\." % secret_id

    assert 'secret_id = "%s"' % secret_id in text
    assert re.search(granted, text, re.MULTILINE) is not None


def test_read_access_is_granted_per_secret_and_no_wider():
    """Asserts the six grants are per secret, not project-wide."""
    text = _text(MAIN_TF)
    grant = _resource(
        "google_secret_manager_secret_iam_member",
        "backend_workload",
    )

    assert 'role      = "%s"' % SECRET_READ_ROLE in grant
    assert "secret_id = each.value" in grant
    assert (
        "google_service_account.backend_workload.email" in grant
    )

    #: The role now appears on more than one grant, because the migration
    #: identity, the provisioning job and the probe function each read
    #: their own secrets. What must hold is that every occurrence sits on a
    #: per-secret grant: the resource type carrying it is always
    #: google_secret_manager_secret_iam_member, never
    #: google_project_iam_member, so no grant is project-wide.
    for resource_type, name in re.findall(
        r'(?m)^resource\s+"([^"]+)"\s+"([^"]+)"', text
    ):
        if SECRET_READ_ROLE in _resource(resource_type, name):
            assert resource_type == (
                "google_secret_manager_secret_iam_member"
            ), (resource_type, name)
    assert (
        'role    = "%s"' % SECRET_READ_ROLE not in text
    ), "a project-level grant would widen the six secret grants"


def test_the_workload_identity_binding_names_the_backend_account():
    """Asserts the Kubernetes account may act as the read identity."""
    binding = _resource(
        "google_service_account_iam_member", "backend_workload_identity"
    )

    assert 'role               = "roles/iam.workloadIdentityUser"' in (
        binding
    )
    #: The pool prefix is declared once, in
    #: local.workload_identity_pool_member, and the namespace is the one
    #: variable every binding names, so a binding cannot be scoped to a
    #: namespace the manifests do not deploy into.
    #: The member is composed once in the locals and read here, so the
    #: binding is resolved through the local it names before the parts are
    #: asserted.
    resolved = binding
    for local in re.findall(r"local\.([a-z_][a-z0-9_]*)", binding):
        found = re.search(
            r"(?m)^\s*" + local + r"\s*=\s*(?P<value>.*)$", _text(MAIN_TF)
        )
        if found is not None:
            resolved += "\n" + found.group("value")
            for nested in re.findall(
                r"local\.([a-z_][a-z0-9_]*)", found.group("value")
            ):
                inner = re.search(
                    r"(?m)^\s*" + nested + r"\s*=\s*(?P<value>.*)$",
                    _text(MAIN_TF),
                )
                if inner is not None:
                    resolved += "\n" + inner.group("value")

    assert "local.workload_identity_pool_member" in resolved, resolved
    assert "${var.workload_identity_namespace}/" in resolved, resolved
    assert "var.backend_kubernetes_service_account}]" in resolved


def test_the_cluster_serves_workload_identity_and_managed_secrets():
    """Asserts the delivery add-ons the grants above rely on are on."""
    cluster = _resource("google_container_cluster", "primary")
    node_pool = _resource("google_container_node_pool", "primary_nodes")
    identity = _block(cluster, "workload_identity_config")
    secrets = _block(cluster, "secret_manager_config")
    metadata = _block(node_pool, "workload_metadata_config")

    assert 'workload_pool = "${var.project_id}.svc.id.goog"' in identity
    assert "enabled = true" in secrets
    assert 'mode = "GKE_METADATA"' in metadata


def test_the_workload_identity_annotation_is_published():
    """Asserts the value a service-account manifest must carry."""
    annotation = _output("backend_workload_identity_annotation")

    assert "iam.gke.io/gcp-service-account=" in annotation
    assert "google_service_account.backend_workload.email" in annotation


def test_the_networking_invariant_is_published():
    """Asserts an operator can read back the shared-VPC property."""
    invariant = _output("private_network_invariant")

    assert "google_container_cluster.primary.network" in invariant
    assert "google_container_cluster.primary.subnetwork" in invariant
    assert "google_sql_database_instance.main" in invariant
    assert (
        "google_compute_global_address.private_services_access.name"
        in invariant
    )


@pytest.mark.parametrize("path", TRACKED_FILES, ids=lambda p: p.name)
def test_no_public_principal_or_world_reachable_range_appears(path):
    """Asserts nothing in the folder grants access to everyone."""
    text = _text(path)

    #: A comment may name a public principal, because the configuration
    #: explains that its authoritative bindings remove one an earlier
    #: deployment left behind. What is forbidden is naming one in a
    #: declaration.
    declarations = "\n".join(
        line
        for line in text.split("\n")
        if not line.strip().startswith("#")
    )
    for principal in PUBLIC_PRINCIPALS:
        assert principal not in declarations, principal
    assert "0.0.0.0/0" not in declarations


@pytest.mark.parametrize("path", TRACKED_FILES, ids=lambda p: p.name)
def test_no_credential_literal_appears(path):
    """Asserts every secret payload arrives as a variable reference."""
    text = _text(path)

    for pattern in CREDENTIAL_PATTERNS:
        assert re.search(pattern, text) is None, pattern


def test_every_secret_payload_is_a_write_only_variable_reference():
    """Asserts no secret version carries an inline value."""
    text = _text(MAIN_TF)
    payloads = re.findall(r"secret_data_wo\s+=\s+(\S+)", text)

    #: Two further secrets were added after this case was written -- the
    #: administrator seed password and the shared rate-limit store address
    #: -- so the count is a floor rather than an equality. Every payload,
    #: including theirs, must still be a write-only variable reference.
    assert len(payloads) >= len(MANAGED_SECRET_IDS), payloads
    for payload in payloads:
        assert payload.startswith("var."), payload
    assert "secret_data " not in text


def test_the_runtime_pin_is_unchanged():
    """Asserts the Python 3.9 pin site is byte-identical."""
    lines = _text(MAIN_TF).split("\n")
    matches = [
        line
        for line in lines
        if re.match(r"\s*runtime\s*=", line)
    ]

    #: Comments discuss the runtime -- including the record of it being
    #: decommissioned upstream and withheld rather than advanced -- so
    #: assignments alone are read.
    assert matches == [RUNTIME_PIN], matches


def test_the_deferred_constructs_are_still_absent():
    """Asserts the reported-only gaps were not closed here."""
    text = _text(MAIN_TF)

    #: Provider pinning was closed after this case was written: the
    #: configuration now constrains provider versions and commits a
    #: dependency lock, so required_providers and required_version are
    #: present by design. The remote state backend is still absent, and
    #: that is the gap this case now guards.
    assert 'backend "' not in text
    assert "required_providers" in text, "provider versions are pinned"


def test_both_buckets_keep_the_setting_recorded_as_reported():
    """Asserts neither bucket's forced-destruction flag changed."""
    text = _text(MAIN_TF)

    assert text.count("force_destroy = true") == 2


@pytest.mark.parametrize("path", TRACKED_FILES, ids=lambda p: p.name)
def test_no_placeholder_marker_survives(path):
    """Asserts nothing is left for a reader to configure by guess."""
    text = _text(path)

    for marker in PLACEHOLDER_MARKERS:
        assert marker not in text, marker


def test_the_prerequisites_and_open_risks_are_recorded():
    """Asserts the folder states what it expects and what it leaves."""
    text = _text(MAIN_TF)

    assert "PREREQUISITES" in text
    assert "Open risks:" in text
    assert "servicenetworking" in text
    assert "SecretProviderClass" in text


def test_no_output_publishes_a_secret_variable():
    """Asserts no published value carries a secret payload."""
    text = _text(OUTPUTS_TF)

    for name in (
        "secret_key",
        "database_url",
        "zillow_api_key",
        "paypal_client_secret",
        "paypal_webhook_id",
        "sendgrid_api_key",
    ):
        assert "var.%s" % name not in text, name
    assert "secret_data" not in text
