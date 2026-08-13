# No output here carries a secret value. Every credential this
# configuration manages is delivered from Secret Manager to the workload
# that reads it, and the secret identifiers below name containers rather
# than payloads, so `terraform output` discloses nothing.

output "region" {
  description = "The region every regional resource is created in, and the location the GKE cluster is addressed by"
  value       = var.region
}

output "kubernetes_cluster_name" {
  description = "The name of the GKE cluster, for gcloud container clusters get-credentials"
  value       = google_container_cluster.primary.name
}

output "kubernetes_cluster_location" {
  description = "The location of the GKE cluster. It is a region and not a zone, so the cluster is addressed with --region and never with --zone"
  value       = google_container_cluster.primary.location
}

output "kubernetes_cluster_is_private" {
  description = "Whether the cluster control plane carries a private endpoint only. While it is true, a client must reach the control plane from the VPC or from an authorized network"
  value       = google_container_cluster.primary.private_cluster_config[0].enable_private_endpoint
}

output "kubernetes_cluster_endpoint" {
  description = "The endpoint for the Kubernetes cluster"
  value       = google_container_cluster.primary.endpoint
}

output "workload_identity_pool" {
  description = "The workload identity pool the cluster is configured with, which is the issuer half of every workload identity member"
  value       = google_container_cluster.primary.workload_identity_config[0].workload_pool
}

output "network_self_link" {
  description = "Self-link of the VPC network every resource attaches to"
  value       = google_compute_network.primary.self_link
}

output "subnetwork_self_link" {
  description = "Self-link of the subnetwork the GKE nodes draw their addresses from"
  value       = google_compute_subnetwork.primary.self_link
}

output "private_service_access_range_name" {
  description = "Name of the reserved range published to the service producer network, from which the Cloud SQL instance draws its private address"
  value       = google_compute_global_address.private_services_access.name
}

output "database_instance_connection_name" {
  description = "The connection name of the Cloud SQL database instance"
  value       = google_sql_database_instance.main.connection_name
}

output "database_name" {
  description = "The name of the database created on the Cloud SQL instance"
  value       = google_sql_database.database.name
}

output "rate_limit_store_host" {
  description = "Private address of the shared rate-limit store. Compose it with the port below into the RATE_LIMIT_STORAGE_URI the workloads read, as redis://<host>:<port>. The address is not a secret; the instance's AUTH string is, and it is published by no output"
  value       = google_redis_instance.rate_limit.host
}

output "rate_limit_store_port" {
  description = "Port of the shared rate-limit store"
  value       = google_redis_instance.rate_limit.port
}

output "backend_service_account_email" {
  description = "Email of the service account the backend workload runs as. It is the value the Kubernetes service account annotation in infrastructure/kubernetes/ must carry"
  value       = google_service_account.backend_workload.email
}

output "kubernetes_namespace" {
  description = "The namespace the workloads run in, which is one half of the workload identity member"
  value       = var.kubernetes_namespace
}

output "backend_kubernetes_service_account" {
  description = "The name of the Kubernetes service account bound to the backend identity, which is the other half of the workload identity member"
  value       = var.backend_kubernetes_service_account
}

output "backend_secret_ids" {
  description = "The Secret Manager secret identifiers the backend reads, keyed by the setting each one supplies. These are names only: no secret payload is emitted by any output in this file"
  value       = local.backend_secret_ids
}

output "admin_provisioner_service_account_email" {
  description = "Email of the service account the administrator provisioning job runs as. It is the value ADMIN_PROVISIONER_GCP_SERVICE_ACCOUNT_EMAIL is rendered from when applying the admin-credential group"
  value       = google_service_account.admin_provisioner.email
}

output "admin_provisioner_kubernetes_service_account" {
  description = "The name of the Kubernetes service account bound to the administrator provisioning identity, which is the other half of that workload identity member"
  value       = var.admin_provisioner_kubernetes_service_account
}

output "admin_provisioner_secret_ids" {
  description = "The Secret Manager secret identifiers the administrator provisioning job reads, keyed by the setting each one supplies. These are names only: no secret payload is emitted by any output in this file"
  value       = local.admin_provisioner_secrets
}

output "storage_bucket_urls" {
  description = "The URLs of the created storage buckets, keyed by resource name"
  value = {
    static_assets = google_storage_bucket.static_assets.url
    data_lake     = google_storage_bucket.data_lake.url
  }
}

output "pubsub_topic_names" {
  description = "The name of the created Pub/Sub topic, keyed by resource name"
  value = {
    main = google_pubsub_topic.main.name
  }
}

output "cloud_function_names" {
  description = "The name of the deployed Cloud Function, keyed by resource name"
  value = {
    function = one(google_cloudfunctions_function.function[*].name)
  }
}

output "cloud_functions_urls" {
  description = "The HTTPS trigger URL of the deployed Cloud Function, keyed by resource name. Invocation is restricted to the principal named by var.cloud_function_invoker_member"
  value = {
    function = one(google_cloudfunctions_function.function[*].https_trigger_url)
  }
}

output "cloud_function_name" {
  description = "The name of the Cloud Function this configuration creates and holds the invoker policy for. scripts/deploy.sh reads the same value from CLOUD_FUNCTION_NAME, so the policy governs the function the script publishes"
  value       = one(google_cloudfunctions_function.function[*].name)
}

output "cloud_function_source_archive" {
  description = "The gs:// address of the source archive the Cloud Function is built from, as one string for an operator reading the plan. scripts/deploy.sh does not read this output: it takes the object name and its digest separately, from cloud_function_source_object and cloud_function_source_md5, so that it can compare the digest of the object it is about to deploy against the one Terraform packaged"
  value = one([
    for f in google_cloudfunctions_function.function :
    "gs://${f.source_archive_bucket}/${f.source_archive_object}"
  ])
}

# The identity of the one source object this configuration publishes, in the
# two parts scripts/deploy.sh needs to deploy the same bytes Terraform
# packaged rather than whatever currently answers to a name. The object name
# carries the content digest, so it is itself content-addressed; the digest
# below is the same base64 MD5 that `gcloud storage objects describe` reports
# as md5_hash, so the script compares like with like and needs no re-encoding.
# Both are null while var.cloud_function_deployment_authorized is false.
output "cloud_function_source_object" {
  description = "The name of the source archive object inside google_storage_bucket.static_assets, carrying the archive's content digest. scripts/deploy.sh reads the same value from CLOUD_FUNCTION_SOURCE_OBJECT"
  value       = one(google_storage_bucket_object.function_source[*].name)
}

output "cloud_function_source_md5" {
  description = "The base64 MD5 of the source archive object, in the encoding gcloud reports as md5_hash. scripts/deploy.sh reads the same value from CLOUD_FUNCTION_SOURCE_MD5 and refuses to deploy an object whose digest differs"
  value       = one(google_storage_bucket_object.function_source[*].md5hash)
}

output "backend_workload_service_account_email" {
  description = "The email of the service account granted read access to the six Secret Manager secrets"
  value       = google_service_account.backend_workload.email
}

output "backend_workload_identity_annotation" {
  description = "The annotation the backend Kubernetes service account manifest must carry for its pods to impersonate the service account that holds the Secret Manager grants"
  value       = "iam.gke.io/gcp-service-account=${google_service_account.backend_workload.email}"
}

output "private_network_invariant" {
  description = "The VPC the GKE cluster and the Cloud SQL instance both sit on, and the reserved range the instance's private address is allocated from. The cluster network and the database network are the same value by variable validation, so a cluster that cannot route to the database is rejected before apply"
  value = {
    cluster_network         = google_container_cluster.primary.network
    cluster_subnetwork      = google_container_cluster.primary.subnetwork
    database_network        = google_sql_database_instance.main.settings[0].ip_configuration[0].private_network
    private_services_range  = google_compute_global_address.private_services_access.name
    private_services_prefix = google_compute_global_address.private_services_access.prefix_length
  }
}

# The three values below are the ones the release pipeline is configured
# with. None is a credential: each is a resource name or a resource path.
output "artifact_registry_repository" {
  description = "Location, repository ID and image host of the container registry the release pipeline publishes to"
  value = {
    location   = google_artifact_registry_repository.containers.location
    repository = google_artifact_registry_repository.containers.repository_id
    host       = "${google_artifact_registry_repository.containers.location}-docker.pkg.dev"
  }
}

output "workload_identity_provider" {
  description = "Full resource name of the OIDC provider the release workflow presents its token to, supplied to the workflow as GCP_WORKLOAD_IDENTITY_PROVIDER"
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "service_account_emails" {
  description = "Email address of each service account this configuration creates, keyed by the role it serves"
  value = {
    deployer         = google_service_account.deployer.email
    gke_nodes        = google_service_account.gke_nodes.email
    backend_workload = google_service_account.backend_workload.email
    cloud_function   = google_service_account.cloud_function.email
  }
}

output "rate_limit_store_endpoint" {
  description = "The host and port of the managed rate-limit store. Both are addresses rather than credentials; the store's AUTH string is not published here and reaches the workload only through the RATE_LIMIT_STORAGE_URI Secret Manager secret"
  value = {
    host = google_redis_instance.rate_limit.host
    port = google_redis_instance.rate_limit.port
  }
}

output "network_name" {
  description = "The name of the VPC network the cluster, its nodes and the database instance all attach to"
  value       = google_compute_network.primary.name
}

output "subnetwork_name" {
  description = "The name of the subnetwork the cluster nodes take their addresses from"
  value       = google_compute_subnetwork.primary.name
}

output "backend_runtime_service_account_email" {
  description = "The email of the service account the backend workload assumes through Workload Identity. It is the value the Kubernetes service account annotation in infrastructure/kubernetes/10-service-accounts.yaml must carry"
  value       = google_service_account.backend_workload.email
}

output "managed_secret_names" {
  description = "The Secret Manager secret identifiers the backend reads, which are also the setting names it reads them as. Identifiers only; no secret payload is emitted by any output in this file"
  value = [
    google_secret_manager_secret.secret_key.secret_id,
    google_secret_manager_secret.database_url.secret_id,
    google_secret_manager_secret.zillow_api_key.secret_id,
    google_secret_manager_secret.paypal_client_secret.secret_id,
    google_secret_manager_secret.paypal_webhook_id.secret_id,
    google_secret_manager_secret.sendgrid_api_key.secret_id,
  ]
}

# The two identities the cluster's workloads assume. These are the values a
# Kubernetes service account is annotated with, and the annotation is the
# last step of the secret delivery path, applied against the cluster rather
# than by this configuration. An email addresses an identity and carries no
# credential. No output in this file reads a secret value; the secret
# versions are written through write-only arguments and published nowhere.
output "workload_service_account_emails" {
  description = "The email of each workload identity, keyed by the Kubernetes service account that may act as it. Annotate each Kubernetes service account with iam.gke.io/gcp-service-account set to the matching value"
  value = {
    (var.backend_kubernetes_service_account)   = google_service_account.backend_workload.email
    (var.migration_kubernetes_service_account) = google_service_account.backend_migrate.email
  }
}

output "kubernetes_cluster_dns_endpoint" {
  description = "The DNS name of the cluster control plane. It is the address a caller outside the cluster's VPC reaches the control plane by, authorized by the IAM permission container.clusters.connect"
  value       = google_container_cluster.primary.control_plane_endpoints_config[0].dns_endpoint_config[0].endpoint
}

output "artifact_registry_image_prefix" {
  description = "The prefix every released image reference carries. An image is published as \"<prefix>/<workload>:<tag>\" and rolled out by the digest that push returns"
  value = format(
    "%s-docker.pkg.dev/%s/%s",
    google_artifact_registry_repository.containers.location,
    var.project_id,
    google_artifact_registry_repository.containers.name,
  )
}

# The secret containers the application reads at startup, by name. The
# names are emitted so a deployment can confirm which containers exist and
# which principals may read them; no version and no payload is read.
output "secret_names" {
  description = "The Secret Manager secret each setting is stored in, keyed by the setting name"
  value       = local.backend_secret_ids
}

# Derived from the bindings themselves rather than from a list of principals,
# so this cannot report a grant that was not made. Each entry is one secret
# and the one identity allowed to read it: the backend runtime identity holds
# all six, the migration identity holds the connection string alone, and the
# provisioning identity holds the two its job declares.
output "secret_accessor_bindings" {
  description = "The secret-and-principal pairs granted roles/secretmanager.secretAccessor. A setting whose secret appears in secret_names but in no pair here is a secret no workload can read"
  value = sort(concat(
    [
      for binding in google_secret_manager_secret_iam_member.backend_workload :
      "${binding.secret_id}:${binding.member}"
    ],
    [
      "${google_secret_manager_secret_iam_member.backend_migrate.secret_id}:${google_secret_manager_secret_iam_member.backend_migrate.member}"
    ],
    [
      for binding in google_secret_manager_secret_iam_member.admin_provisioner :
      "${binding.secret_id}:${binding.member}"
    ],
  ))
}

output "cloud_function_runtime_service_account_email" {
  description = "The Google service account email the Cloud Function runs as, holding read access to the two secrets its environment declares"
  value       = google_service_account.cloud_function.email
}
