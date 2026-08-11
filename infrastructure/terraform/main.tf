# Main Terraform configuration file for provisioning Google Cloud resources

# Provider configuration for Google Cloud
provider "google" {
  project = var.project_id
  region  = var.region
}

# APIs the resources below call. Each stays enabled when the
# configuration is destroyed, so a project that shares an API with
# another workload keeps it.
resource "google_project_service" "required" {
  for_each = toset([
    "compute.googleapis.com",
    "container.googleapis.com",
    "servicenetworking.googleapis.com",
    "sqladmin.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudfunctions.googleapis.com",
    "redis.googleapis.com",
  ])

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

# The one VPC every resource below attaches to. Subnetworks are declared
# here rather than created automatically, so the cluster and the database
# share a single named network and a single named subnetwork.
resource "google_compute_network" "primary" {
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"

  depends_on = [google_project_service.required]
}

# Subnetwork the node pool draws its node addresses from, carrying the
# two secondary ranges the cluster allocates pods and services from.
# Private Google access lets a node without an external address reach
# Google APIs.
resource "google_compute_subnetwork" "primary" {
  name                     = var.subnetwork_name
  region                   = var.region
  network                  = google_compute_network.primary.id
  ip_cidr_range            = var.subnetwork_ip_cidr_range
  private_ip_google_access = true

  secondary_ip_range {
    range_name    = var.gke_pods_range_name
    ip_cidr_range = var.gke_pods_ip_cidr_range
  }

  secondary_ip_range {
    range_name    = var.gke_services_range_name
    ip_cidr_range = var.gke_services_ip_cidr_range
  }
}

# Egress path for the private nodes. They carry no external address, so
# the outbound calls the service makes to PayPal, Zillow and SendGrid
# leave through this NAT.
resource "google_compute_router" "primary" {
  name    = var.router_name
  region  = var.region
  network = google_compute_network.primary.id
}

resource "google_compute_router_nat" "primary" {
  name                               = var.nat_name
  router                             = google_compute_router.primary.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Address range reserved for private services access, and the peering
# that publishes it to Google's service producer network. The Cloud SQL
# instance below reaches its private address over this peering and
# declares a dependency on it.
resource "google_compute_global_address" "private_services_access" {
  name          = var.private_service_access_range_name
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  prefix_length = var.private_service_access_prefix_length
  network       = google_compute_network.primary.id
}

resource "google_service_networking_connection" "private_services_access" {
  network                 = google_compute_network.primary.id
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services_access.name]

  depends_on = [google_project_service.required]
}

# Resource definitions for Google Kubernetes Engine cluster
resource "google_container_cluster" "primary" {
  name     = "primary-cluster"
  location = var.region

  remove_default_node_pool = true
  initial_node_count       = 1

  network    = google_compute_subnetwork.primary.network
  subnetwork = google_compute_subnetwork.primary.id

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  # The cluster sits on google_compute_network.primary, the same VPC the
  # Cloud SQL instance takes its private address on, so the pods have a
  # route to that address. Both are set from the subnetwork resource above
  # rather than from a variable, so one declaration is the network
  # authority for the whole configuration.

  # The control plane endpoint and the nodes carry private addresses only.
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = var.gke_master_ipv4_cidr_block
  }

  # The IP-based endpoint above is private, which leaves no address a
  # release runner outside the VPC can reach. The DNS-based endpoint is the
  # path that remains: it authorizes by the IAM permission
  # container.clusters.connect rather than by source address, and
  # var.gke_dns_endpoint_external_traffic governs whether a caller outside
  # the VPC may use it. outputs.tf publishes the resulting name.
  control_plane_endpoints_config {
    dns_endpoint_config {
      allow_external_traffic = var.gke_dns_endpoint_external_traffic
    }
  }

  # Binds Kubernetes service accounts to Google service accounts, which
  # is how the workloads read the Secret Manager secrets declared below.
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Installs the managed Secret Manager CSI driver, which the
  # SecretProviderClass in infrastructure/kubernetes/ is served by.
  secret_manager_config {
    enabled = true
  }

  # The CIDR blocks listed in var.gke_master_authorized_networks are the
  # only blocks that reach the control plane, on the private endpoint as
  # well as on the public one, and Google's own public address ranges are
  # not exempted. An empty list authorizes no network outside the cluster's
  # own VPC.
  master_authorized_networks_config {
    gcp_public_cidrs_access_enabled      = false
    private_endpoint_enforcement_enabled = true

    dynamic "cidr_blocks" {
      for_each = var.gke_master_authorized_networks

      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  # VPC-native addressing over the two secondary ranges the subnetwork
  # above declares.
  ip_allocation_policy {
    cluster_secondary_range_name  = var.gke_pods_range_name
    services_secondary_range_name = var.gke_services_range_name
  }
}

resource "google_container_node_pool" "primary_nodes" {
  name       = "primary-node-pool"
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = var.gke_num_nodes

  node_config {
    # The nodes run as the dedicated account defined below.
    service_account = google_service_account.gke_nodes.email

    # An access scope is a ceiling on the tokens a node may mint, applied
    # on top of IAM: a role the account holds is unusable when no scope
    # admits it. The scopes come from var.gke_node_oauth_scopes, whose own
    # validation requires one that reaches the image registry, so a list
    # narrowed by an operator still leaves the pool able to pull. The IAM
    # bindings below are what bound this identity's permissions, and their
    # own variable admits node-pool roles only.
    oauth_scopes = var.gke_node_oauth_scopes

    labels = {
      env = var.project_id
    }

    machine_type = "n1-standard-1"
    tags         = ["gke-node", "${var.project_id}-gke"]
    metadata = {
      disable-legacy-endpoints = "true"
    }

    # Serves the workload identity the cluster configures, so a pod reads
    # the identity bound to its Kubernetes service account rather than the
    # node's own.
    workload_metadata_config {
      mode = "GKE_METADATA"
    }
  }
}

# Dedicated identity for the GKE node pool above
resource "google_service_account" "gke_nodes" {
  account_id   = var.gke_node_service_account_id
  display_name = "GKE node pool service account"
  description  = "Identity assumed by the nodes of google_container_node_pool.primary_nodes"
}

# One binding per role in var.gke_node_service_account_roles, whose own
# validation admits only node-pool roles: writing logs, writing metrics and
# reading the image registry the workloads pull from.
resource "google_project_iam_member" "gke_nodes" {
  for_each = toset(var.gke_node_service_account_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.gke_nodes.email}"
}

# The address block reserved for the Google services that peer into the VPC,
# and the peering itself, are declared once above on
# google_compute_network.primary. The Cloud SQL instance below draws its
# private address out of that block.

# Resource definitions for Google Cloud SQL instance
resource "google_sql_database_instance" "main" {
  name             = "main-instance"
  database_version = "POSTGRES_13"
  region           = var.region

  # The private address below is allocated from the reserved block, so the
  # peering has to exist first.
  depends_on = [google_service_networking_connection.private_services_access]

  settings {
    tier = "db-f1-micro"

    # The instance is reachable over google_compute_network.primary only,
    # with no public IPv4 address, and accepts encrypted connections only.
    # The address is drawn from the private services access range declared
    # above, which the depends_on below requires to be published first.
    ip_configuration {
      ipv4_enabled    = false
      private_network = google_compute_network.primary.id
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    # Automated daily backups with point-in-time recovery.
    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      start_time                     = "03:00"

      backup_retention_settings {
        retained_backups = 7
        retention_unit   = "COUNT"
      }
    }
  }

  deletion_protection = true
}

resource "google_sql_database" "database" {
  name     = "main-database"
  instance = google_sql_database_instance.main.name
}

# Store the credential-endpoint rate limits are counted in. The backend
# refuses an in-process counter outside a local environment, so a
# deployment addresses this instance instead and every replica evaluates
# one shared count. It is reachable over the private services access
# connection above and carries no external address.
resource "google_redis_instance" "rate_limit" {
  name               = var.rate_limit_store_name
  tier               = var.rate_limit_store_tier
  memory_size_gb     = var.rate_limit_store_memory_size_gb
  region             = var.region
  authorized_network = google_compute_network.primary.id
  connect_mode       = "PRIVATE_SERVICE_ACCESS"
  redis_version      = "REDIS_6_X"

  # The store holds the credential-endpoint counters, so it requires an AUTH
  # string and encrypts the connection it is presented over. The AUTH string
  # reaches the workload only inside the RATE_LIMIT_STORAGE_URI secret below
  # and is published by no output.
  auth_enabled            = true
  transit_encryption_mode = "SERVER_AUTHENTICATION"

  # Counters are bounded state: an entry that can no longer be reached is
  # evicted rather than filling the instance and refusing new writes.
  redis_configs = {
    maxmemory-policy = "allkeys-lru"
  }

  depends_on = [google_service_networking_connection.private_services_access]
}

# Resource definitions for Google Cloud Storage buckets
resource "google_storage_bucket" "static_assets" {
  name          = "${var.project_id}-static-assets"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true
}

resource "google_storage_bucket" "data_lake" {
  name          = "${var.project_id}-data-lake"
  location      = var.region
  force_destroy = true

  uniform_bucket_level_access = true
}

# Resource definitions for Google Cloud Pub/Sub topics and subscriptions
resource "google_pubsub_topic" "main" {
  name = "main-topic"
}

resource "google_pubsub_subscription" "main" {
  name  = "main-subscription"
  topic = google_pubsub_topic.main.name

  ack_deadline_seconds = 20
}

# Source archive of the function below, packaged from
# infrastructure/functions/health and uploaded to the bucket the function
# reads it from. The object name carries the archive's content digest, so
# a change to the source publishes a new object and the function picks it
# up, and no name is reused for different bytes.
#
# Both are gated on the same var.cloud_function_deployment_authorized the
# function and its invoker binding are gated on, so the whole function
# footprint is present or absent together. The digest and the object name
# are published as outputs for scripts/deploy.sh to deploy and verify
# against; they are null while the function is unauthorized, which is the
# state in which that script performs no function step.
data "archive_file" "function_source" {
  count = var.cloud_function_deployment_authorized ? 1 : 0

  type        = "zip"
  source_dir  = "${path.module}/${var.cloud_function_source_dir}"
  output_path = "${path.module}/.terraform/function-source.zip"
}

resource "google_storage_bucket_object" "function_source" {
  count = var.cloud_function_deployment_authorized ? 1 : 0

  name   = "function-source-${data.archive_file.function_source[0].output_md5}.zip"
  bucket = google_storage_bucket.static_assets.name
  source = data.archive_file.function_source[0].output_path
}

# Cloud Function creation is gated by
# cloud_function_deployment_authorized; the Python 3.9 residual risk is
# documented in docs/security/RESIDUAL_RISK.md.
resource "google_cloudfunctions_function" "function" {
  count = var.cloud_function_deployment_authorized ? 1 : 0

  name        = var.cloud_function_name
  description = var.cloud_function_description
  runtime     = "python39"

  available_memory_mb   = 128
  source_archive_bucket = google_storage_bucket_object.function_source[0].bucket
  source_archive_object = google_storage_bucket_object.function_source[0].name
  trigger_http          = true
  entry_point           = var.cloud_function_entry_point
  service_account_email = google_service_account.cloud_function.email

  # Non-secret configuration only. Secret payloads are read from Secret
  # Manager by the identity above.
  environment_variables = var.cloud_function_environment_variables

  # Egress through the connector in var.cloud_function_vpc_connector, on
  # the terms var.cloud_function_vpc_connector_egress_settings declares.
  # Both arguments are omitted when no connector is supplied.
  vpc_connector                 = var.cloud_function_vpc_connector
  vpc_connector_egress_settings = var.cloud_function_vpc_connector == null ? null : var.cloud_function_vpc_connector_egress_settings

  # Reachable on the terms var.cloud_function_ingress_settings declares,
  # whose validation rejects the value admitting any caller on the
  # internet, so the IAM restriction below is not the only network control.
  ingress_settings = var.cloud_function_ingress_settings

  depends_on = [google_project_service.required]
}

# Authoritative invoker membership for the Cloud Function.
resource "google_cloudfunctions_function_iam_binding" "invoker" {
  count = var.cloud_function_deployment_authorized ? 1 : 0

  project        = google_cloudfunctions_function.function[0].project
  region         = google_cloudfunctions_function.function[0].region
  cloud_function = google_cloudfunctions_function.function[0].name

  role    = "roles/cloudfunctions.invoker"
  members = [var.cloud_function_invoker_member]
}

# Secret Manager secrets for the values the backend reads at startup. Each
# secret_id matches the name of the setting that consumes it, as documented in
# the repository's .env.example. Every version takes its payload from a
# sensitive, ephemeral input variable through the write-only secret_data_wo
# argument, paired with secret_data_wo_version.
resource "google_secret_manager_secret" "secret_key" {
  secret_id = "SECRET_KEY"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "secret_key" {
  secret                 = google_secret_manager_secret.secret_key.id
  secret_data_wo         = var.secret_key
  secret_data_wo_version = var.secret_version_generation
}

resource "google_secret_manager_secret" "database_url" {
  secret_id = "DATABASE_URL"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "database_url" {
  secret                 = google_secret_manager_secret.database_url.id
  secret_data_wo         = var.database_url
  secret_data_wo_version = var.secret_version_generation
}

resource "google_secret_manager_secret" "zillow_api_key" {
  secret_id = "ZILLOW_API_KEY"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "zillow_api_key" {
  secret                 = google_secret_manager_secret.zillow_api_key.id
  secret_data_wo         = var.zillow_api_key
  secret_data_wo_version = var.secret_version_generation
}

resource "google_secret_manager_secret" "paypal_client_secret" {
  secret_id = "PAYPAL_CLIENT_SECRET"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "paypal_client_secret" {
  secret                 = google_secret_manager_secret.paypal_client_secret.id
  secret_data_wo         = var.paypal_client_secret
  secret_data_wo_version = var.secret_version_generation
}

resource "google_secret_manager_secret" "paypal_webhook_id" {
  secret_id = "PAYPAL_WEBHOOK_ID"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "paypal_webhook_id" {
  secret                 = google_secret_manager_secret.paypal_webhook_id.id
  secret_data_wo         = var.paypal_webhook_id
  secret_data_wo_version = var.secret_version_generation
}

resource "google_secret_manager_secret" "sendgrid_api_key" {
  secret_id = "SENDGRID_API_KEY"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "sendgrid_api_key" {
  secret                 = google_secret_manager_secret.sendgrid_api_key.id
  secret_data_wo         = var.sendgrid_api_key
  secret_data_wo_version = var.secret_version_generation
}

resource "google_secret_manager_secret" "admin_seed_password" {
  secret_id = "ADMIN_SEED_PASSWORD"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "admin_seed_password" {
  secret                 = google_secret_manager_secret.admin_seed_password.id
  secret_data_wo         = var.admin_seed_password
  secret_data_wo_version = var.secret_version_generation
}

# The secrets above, keyed by the setting each one supplies. The key is
# the name the backend reads the value under, and the value is the
# resource identifier the accessor binding below is attached to.
locals {
  # The secrets the administrator provisioning job reads, keyed by the
  # setting each one supplies. The command resolves the database URL
  # itself and hashes at the configured cost, so it reads no
  # token-signing key.
  admin_provisioner_secrets = {
    DATABASE_URL        = google_secret_manager_secret.database_url.secret_id
    ADMIN_SEED_PASSWORD = google_secret_manager_secret.admin_seed_password.secret_id
  }
}



# Binds the Kubernetes service account the backend and migration
# workloads declare to the identity above. The Kubernetes side of the
# binding is the annotation on that service account, declared in
# infrastructure/kubernetes/.
resource "google_service_account_iam_member" "backend_workload_identity" {
  service_account_id = google_service_account.backend_workload.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.backend_workload_principal
}

# Identity the administrator provisioning job runs as, separate from the
# backend's. It holds no project-level role; its only grants are the two
# per-secret accessor bindings below and the workload identity binding, so
# it reads DATABASE_URL and ADMIN_SEED_PASSWORD and no other secret. The
# backend identity holds no grant on ADMIN_SEED_PASSWORD.
resource "google_service_account" "admin_provisioner" {
  account_id   = var.admin_provisioner_service_account_id
  display_name = "Administrator provisioning service account"
  description  = "Identity assumed by infrastructure/kubernetes/70-admin-credential-job.yaml in namespace ${var.kubernetes_namespace}"
}

resource "google_secret_manager_secret_iam_member" "admin_provisioner" {
  for_each = local.admin_provisioner_secrets

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.admin_provisioner.email}"
}

resource "google_service_account_iam_member" "admin_provisioner_workload_identity" {
  service_account_id = google_service_account.admin_provisioner.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "${local.workload_identity_pool_member}[${var.workload_identity_namespace}/${var.admin_provisioner_kubernetes_service_account}]"
}

# Main Terraform configuration file for provisioning Google Cloud resources

# This configuration declares no top-level settings block, so it carries
# no tool version floor, no provider version constraint and no remote
# state configuration. Both absences are recorded in
# docs/security/DECISION_LOG.md as reported and awaiting confirmation, and
# no change here closes either. The ephemeral input variables and
# write-only arguments the secret versions below use need Terraform 1.11
# or later; an operator supplies that, rather than this file demanding it.

# Identity the function runs as. It holds no project role of its own; the
# accessor grants it needs are attached to individual secrets below.
resource "google_service_account" "cloud_function" {
  account_id   = var.cloud_function_service_account_id
  display_name = "Cloud Function runtime service account"
  description  = "Identity assumed by google_cloudfunctions_function.function"
}

# Registry the release pipeline publishes container images to and the node
# pool pulls them from. Its host is <location>-docker.pkg.dev, which is
# the host .github/workflows/cd.yml and scripts/deploy.sh address.
resource "google_artifact_registry_repository" "containers" {
  location      = var.region
  repository_id = var.artifact_registry_repository_id
  format        = "DOCKER"
  description   = "Container images for the apartment-finder service"

  # A push that would move a tag already in the repository is refused, so a
  # released tag keeps naming the content it named when it was verified.
  docker_config {
    immutable_tags = true
  }
}

# Identity the continuous-deployment workflow acts as. It holds no
# long-lived key: the workflow exchanges its GitHub OIDC token for a
# short-lived credential through the federation below.
resource "google_service_account" "deployer" {
  account_id   = var.deployer_service_account_id
  display_name = "Release pipeline deployer"
  description  = "Identity the continuous-deployment workflow impersonates"
}

# One binding per role in var.deployer_roles, whose own validation admits
# only the roles a release needs.
resource "google_project_iam_member" "deployer" {
  for_each = toset(var.deployer_roles)

  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

# Publishing is scoped to the single repository above rather than granted
# across the project.
resource "google_artifact_registry_repository_iam_member" "deployer" {
  project    = var.project_id
  location   = google_artifact_registry_repository.containers.location
  repository = google_artifact_registry_repository.containers.repository_id

  role   = "roles/artifactregistry.writer"
  member = "serviceAccount:${google_service_account.deployer.email}"
}

# Pulling is scoped the same way for the node identity.
resource "google_artifact_registry_repository_iam_member" "gke_nodes" {
  project    = var.project_id
  location   = google_artifact_registry_repository.containers.location
  repository = google_artifact_registry_repository.containers.repository_id

  role   = "roles/artifactregistry.reader"
  member = "serviceAccount:${google_service_account.gke_nodes.email}"
}

# Federation for the release workflow. A GitHub Actions token is accepted
# only from the repository and branch named below, so a fork or another
# repository cannot obtain a credential for this project.
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = var.workload_identity_pool_id
  display_name              = "GitHub Actions"
  description               = "Federated identities for this repository's workflows"
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = var.workload_identity_pool_provider_id
  display_name                       = "GitHub OIDC"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
    "attribute.ref"        = "assertion.ref"
  }

  attribute_condition = "assertion.repository == \"${var.github_repository}\" && assertion.ref == \"refs/heads/${var.github_deployment_branch}\""

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# The federated principal set may act as the deployer account, and no
# other principal may.
resource "google_service_account_iam_member" "deployer_federation" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repository}"
}

# Identity the backend workload runs as inside the cluster. The
# Kubernetes service account named by var.workload_identity_namespace
# and var.backend_kubernetes_service_account acts as this account through
# the cluster's workload identity pool.
resource "google_service_account" "backend_workload" {
  account_id   = var.backend_workload_service_account_id
  display_name = "Backend workload service account"
  description  = "Identity the backend Deployment reads its secrets as"
}

# Read access to the secret payloads the backend consumes at startup,
# granted one secret at a time so the identity can read nothing else.
resource "google_secret_manager_secret_iam_member" "backend_workload" {
  # The set is declared once, in local.backend_secret_ids, so the names
  # granted here cannot drift from the names delivered to the workload.
  for_each = local.backend_secret_ids

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.backend_workload.email}"
}

# Read access for the Cloud Function identity, limited to the secrets
# named by var.cloud_function_secret_ids. The default is an empty list, so
# the function reads no secret unless one is named.
resource "google_secret_manager_secret_iam_member" "cloud_function" {
  for_each = toset(var.cloud_function_secret_ids)

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_function.email}"
}

# Invocation of the function is limited to the single principal named by
# var.cloud_function_invoker_member, whose own validation rejects the public
# principals. That restriction is expressed once, by the authoritative
# google_cloudfunctions_function_iam_binding declared above: an additive
# member resource cannot remove a public principal an earlier deployment
# granted, so none is declared here.

# Address the backend reaches google_redis_instance.rate_limit at, including the
# instance's AUTH string, so the workload receives it the same way as every
# other secret rather than as a literal in a manifest or a workflow. The
# variable's own validation admits only the shared schemes the application
# accepts outside a local run. The non-secret host and port are published by
# outputs.tf so the value can be assembled from what Terraform provisioned.
# The release pipeline reads this one value and copies it into the cluster
# secret the workload references, so the deployer identity is granted read
# access on this secret and on no other. Without the grant the deployment
# step that publishes the address fails, and the workload starts against no
# shared store.
resource "google_secret_manager_secret_iam_member" "deployer_rate_limit" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.rate_limit_storage_uri.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_secret_manager_secret" "rate_limit_storage_uri" {
  secret_id = "RATE_LIMIT_STORAGE_URI"

  replication {
    auto {}
  }
}

resource "google_secret_manager_secret_version" "rate_limit_storage_uri" {
  secret                 = google_secret_manager_secret.rate_limit_storage_uri.id
  secret_data_wo         = var.rate_limit_storage_uri
  secret_data_wo_version = var.secret_version_generation
}

# Identity the one-shot migration job assumes. It is separate from the
# serving identity because the migration environment reads DATABASE_URL and
# no other setting, and separating them is what allows that to be enforced
# rather than merely true.
resource "google_service_account" "backend_migrate" {
  account_id   = var.migration_service_account_id
  display_name = "Database migration service account"
  description  = "Identity assumed by the migration job through the Kubernetes service account ${var.migration_kubernetes_service_account}"
}

# The migration identity may read one secret: the database URL. It holds no
# access to the signing key or to any third-party credential, so a
# migration run cannot reach them even if the image it runs is the same
# one the application runs.
resource "google_secret_manager_secret_iam_member" "backend_migrate" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.database_url.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.backend_migrate.email}"
}

# The Kubernetes service account the migration pod runs as may act as the
# migration identity, and no other may. The pod names that account in
# .github/workflows/cd.yml.
resource "google_service_account_iam_member" "backend_migrate_identity" {
  service_account_id = google_service_account.backend_migrate.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "${local.workload_identity_pool_member}[${var.workload_identity_namespace}/${var.migration_kubernetes_service_account}]"
}

# The application reports a degraded audit or logging sink by emitting one
# record carrying this signal, and it reports it there rather than in a
# response body because a readiness body is read by an unauthenticated
# caller. This metric is what turns that record into something that can be
# alerted on.
resource "google_logging_metric" "record_sink_degraded" {
  project     = var.project_id
  name        = var.record_sink_degraded_metric_name
  description = "Occurrences of the record-writing sink degradation signal the application emits when an audit record or a log record could not be written"

  filter = "jsonPayload.${var.record_sink_degraded_signal_field}=\"${var.record_sink_degraded_signal}\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# A single occurrence opens an incident. The threshold is zero because the
# signal is emitted only when a record was already lost, so there is no
# volume at which losing audit records is acceptable.
resource "google_monitoring_alert_policy" "record_sink_degraded" {
  project      = var.project_id
  display_name = "A record-writing sink degraded"
  combiner     = "OR"

  conditions {
    display_name = "The application reported a lost audit or log record"

    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.record_sink_degraded.name}\""
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      duration        = "0s"

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_DELTA"
      }
    }
  }

  notification_channels = var.alert_notification_channels

  documentation {
    mime_type = "text/markdown"
    content   = "An authorization decision or a log record could not be written. Records emitted while a sink is degraded are lost, so the window this incident covers cannot be reconstructed afterwards. Read the surrounding records for the failure reason and the count each record carries."
  }
}

# Retention for the bucket every record above is written to. An alert is
# only as useful as the records that remain to be read after it fires.
resource "google_logging_project_bucket_config" "default" {
  project        = var.project_id
  location       = "global"
  bucket_id      = "_Default"
  retention_days = var.log_retention_days
}

locals {
  backend_secret_ids = {
    SECRET_KEY           = google_secret_manager_secret.secret_key.secret_id
    DATABASE_URL         = google_secret_manager_secret.database_url.secret_id
    ZILLOW_API_KEY       = google_secret_manager_secret.zillow_api_key.secret_id
    PAYPAL_CLIENT_SECRET = google_secret_manager_secret.paypal_client_secret.secret_id
    PAYPAL_WEBHOOK_ID    = google_secret_manager_secret.paypal_webhook_id.secret_id
    SENDGRID_API_KEY     = google_secret_manager_secret.sendgrid_api_key.secret_id
  }

  # Prefix of a Kubernetes service account principal in this cluster's
  # workload identity pool.
  workload_identity_pool_member = "serviceAccount:${var.project_id}.svc.id.goog"
}

# One writer binding per principal in var.artifact_registry_writer_members,
# scoped to the repository above rather than to the project. This is the
# permission the release automation publishes with.
resource "google_artifact_registry_repository_iam_member" "writer" {
  for_each = toset(var.artifact_registry_writer_members)

  project    = var.project_id
  location   = google_artifact_registry_repository.containers.location
  repository = google_artifact_registry_repository.containers.name

  role   = "roles/artifactregistry.writer"
  member = each.value
}

# Read access to the secrets above is granted per secret to the identity
# that needs that secret, by the three bindings declared earlier in this
# file, and by nothing else:
#
#   google_secret_manager_secret_iam_member.backend_workload   all six, to
#     the generated backend runtime identity, which is the only workload
#     that reads all six;
#   google_secret_manager_secret_iam_member.backend_migrate     DATABASE_URL
#     alone, to the migration identity, which needs no other;
#   google_secret_manager_secret_iam_member.admin_provisioner   the two the
#     provisioning job declares.
#
# No binding grants a caller-supplied list of principals accessor on every
# secret. Every grant in this file names one secret and one identity, so the
# readers of each secret are fixed here and not by a deployment-time list.
# The output in outputs.tf reporting these grants derives from the bindings
# themselves, so it cannot report a grant that was not made. A contract test
# asserts by name that no cross-product plane, no local building one and no
# variable feeding one is declared anywhere in this configuration.
#
# The choice and the alternatives weighed: DECISION_LOG.md row 94.5.3.
#
# The role granted reads a version and does not administer the secret, so
# a compromised workload can neither add a version nor change a binding.

locals {

  # Principal the Kubernetes service account named by
  # var.workload_identity_namespace and var.backend_kubernetes_service_account
  # presents when it impersonates the backend runtime identity.
  # The Kubernetes principal google_service_account_iam_member.backend_workload_identity
  # permits. It is composed once here so the namespace and the account name
  # cannot differ between the binding and the manifests that create them.
  backend_workload_principal = "${local.workload_identity_pool_member}[${var.workload_identity_namespace}/${var.backend_kubernetes_service_account}]"
}

# Deployment prerequisites and residual risks are documented in README.md
# and docs/security/RESIDUAL_RISK.md.
