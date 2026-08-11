variable "project_id" {
  description = "The ID of the Google Cloud project"
  type        = string
}

variable "region" {
  description = "The region to deploy resources in"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "The zone to deploy resources in"
  type        = string
  default     = "us-central1-a"
}

variable "cluster_name" {
  description = "The name of the GKE cluster"
  type        = string
  default     = "main-cluster"
}

variable "database_instance_name" {
  description = "The name of the Cloud SQL instance"
  type        = string
  default     = "main-db-instance"
}

variable "storage_bucket_name_raw" {
  description = "The name of the storage bucket for raw data"
  type        = string
  default     = "raw-data-bucket"
}

variable "storage_bucket_name_processed" {
  description = "The name of the storage bucket for processed data"
  type        = string
  default     = "processed-data-bucket"
}

variable "pubsub_topic_name_raw" {
  description = "The name of the Pub/Sub topic for raw data"
  type        = string
  default     = "raw-data-topic"
}

variable "pubsub_topic_name_processed" {
  description = "The name of the Pub/Sub topic for processed data"
  type        = string
  default     = "processed-data-topic"
}

variable "cloud_function_name_ingest" {
  description = "The name of the Cloud Function for data ingestion"
  type        = string
  default     = "data-ingest-function"
}

variable "cloud_function_name_process" {
  description = "The name of the Cloud Function for data processing"
  type        = string
  default     = "data-process-function"
}

variable "cloud_function_name_analyze" {
  description = "The name of the Cloud Function for data analysis"
  type        = string
  default     = "data-analyze-function"
}

variable "gke_num_nodes" {
  description = "Number of nodes in the primary GKE node pool, applied as node_count on google_container_node_pool.primary_nodes"
  type        = number
  default     = 1

  validation {
    condition     = var.gke_num_nodes == floor(var.gke_num_nodes) && var.gke_num_nodes >= 1 && var.gke_num_nodes <= 100
    error_message = "The node count must be a whole number between 1 and 100. Zero, fractional and negative values are rejected."
  }
}

variable "network_name" {
  description = "Name of the VPC network google_compute_network.primary creates. Every other resource attaches to it: the GKE cluster through its subnetwork, and the Cloud SQL instance through settings.ip_configuration.private_network"
  type        = string
  default     = "apartment-finder-vpc"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.network_name))
    error_message = "The network name must be 1 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "subnetwork_name" {
  description = "Name of the subnetwork google_compute_subnetwork.primary creates. google_container_cluster.primary attaches to that resource by reference rather than by name, so the cluster and the created subnetwork cannot name two different subnetworks"
  type        = string
  default     = "apartment-finder-subnet"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.subnetwork_name))
    error_message = "The subnetwork name must be 1 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "subnetwork_ip_cidr_range" {
  description = "Primary CIDR range of google_compute_subnetwork.primary, from which the GKE nodes draw their addresses"
  type        = string
  default     = "10.10.0.0/20"

  validation {
    condition     = can(cidrhost(var.subnetwork_ip_cidr_range, 0))
    error_message = "The subnetwork range must be a valid CIDR block, such as 10.10.0.0/20."
  }
}

variable "gke_pods_range_name" {
  description = "Name of the secondary range GKE allocates pod addresses from, declared on google_compute_subnetwork.primary and named again as ip_allocation_policy.cluster_secondary_range_name"
  type        = string
  default     = "gke-pods"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.gke_pods_range_name))
    error_message = "The pod range name must be 1 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "gke_pods_ip_cidr_range" {
  description = "CIDR range of the secondary range named by var.gke_pods_range_name"
  type        = string
  default     = "10.20.0.0/16"

  validation {
    condition     = can(cidrhost(var.gke_pods_ip_cidr_range, 0))
    error_message = "The pod range must be a valid CIDR block, such as 10.20.0.0/16."
  }
}

variable "gke_services_range_name" {
  description = "Name of the secondary range GKE allocates service addresses from, declared on google_compute_subnetwork.primary and named again as ip_allocation_policy.services_secondary_range_name"
  type        = string
  default     = "gke-services"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.gke_services_range_name))
    error_message = "The service range name must be 1 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "gke_services_ip_cidr_range" {
  description = "CIDR range of the secondary range named by var.gke_services_range_name"
  type        = string
  default     = "10.30.0.0/20"

  validation {
    condition     = can(cidrhost(var.gke_services_ip_cidr_range, 0))
    error_message = "The service range must be a valid CIDR block, such as 10.30.0.0/20."
  }
}

variable "gke_master_ipv4_cidr_block" {
  description = "CIDR range of the private control plane, applied as private_cluster_config.master_ipv4_cidr_block on google_container_cluster.primary. It must not overlap the subnetwork or either secondary range"
  type        = string
  default     = "172.16.0.0/28"

  validation {
    condition     = can(cidrhost(var.gke_master_ipv4_cidr_block, 0))
    error_message = "The control plane range must be a valid CIDR block, such as 172.16.0.0/28."
  }

  validation {
    condition     = tonumber(split("/", trimspace(var.gke_master_ipv4_cidr_block))[1]) == 28
    error_message = "The control plane range must carry a prefix length of exactly 28, which is the size the cluster requires."
  }
}

variable "router_name" {
  description = "Name of the Cloud Router google_compute_router.primary creates, which carries the NAT below"
  type        = string
  default     = "apartment-finder-router"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.router_name))
    error_message = "The router name must be 1 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "nat_name" {
  description = "Name of the Cloud NAT google_compute_router_nat.primary creates, which is the egress path of the private nodes"
  type        = string
  default     = "apartment-finder-nat"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.nat_name))
    error_message = "The NAT name must be 1 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "private_service_access_range_name" {
  description = "Name of the reserved range google_compute_global_address.private_services_access creates and google_service_networking_connection.private_services_access publishes, from which the Cloud SQL instance draws its private address"
  type        = string
  default     = "apartment-finder-psa-range"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.private_service_access_range_name))
    error_message = "The reserved range name must be 1 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "private_service_access_prefix_length" {
  description = "Prefix length of the reserved private services access range, applied as prefix_length on google_compute_global_address.private_services_access"
  type        = number
  default     = 16

  validation {
    condition     = var.private_service_access_prefix_length == floor(var.private_service_access_prefix_length) && var.private_service_access_prefix_length >= 16 && var.private_service_access_prefix_length <= 24
    error_message = "The reserved range prefix length must be a whole number between 16 and 24, which is the span Google accepts for private services access."
  }
}

variable "rate_limit_store_name" {
  description = "Name of the Memorystore instance google_redis_instance.rate_limit creates, which is the shared store the credential-endpoint rate limits are counted in"
  type        = string
  default     = "apartment-finder-rate-limit"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,38}[a-z0-9])?$", var.rate_limit_store_name))
    error_message = "The store name must be 1 to 40 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "rate_limit_store_tier" {
  description = "Service tier of google_redis_instance.rate_limit"
  type        = string
  default     = "BASIC"

  validation {
    condition     = contains(["BASIC", "STANDARD_HA"], var.rate_limit_store_tier)
    error_message = "The store tier must be BASIC or STANDARD_HA."
  }
}

variable "rate_limit_store_memory_size_gb" {
  description = "Memory of google_redis_instance.rate_limit, in gibibytes"
  type        = number
  default     = 1

  validation {
    condition     = var.rate_limit_store_memory_size_gb == floor(var.rate_limit_store_memory_size_gb) && var.rate_limit_store_memory_size_gb >= 1 && var.rate_limit_store_memory_size_gb <= 300
    error_message = "The store memory must be a whole number of gibibytes between 1 and 300."
  }
}


variable "kubernetes_namespace" {
  description = "Kubernetes namespace the workloads run in. It is one half of the workload identity member on google_service_account_iam_member.backend_workload_identity and must match the namespace declared in infrastructure/kubernetes/"
  type        = string
  default     = "apartment-finder"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.kubernetes_namespace))
    error_message = "The namespace must be 1 to 63 characters of lowercase letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

variable "backend_kubernetes_service_account" {
  description = "Name of the Kubernetes service account the backend and migration workloads declare. It is the other half of the workload identity member and must match the service account declared in infrastructure/kubernetes/"
  type        = string
  default     = "backend"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.backend_kubernetes_service_account))
    error_message = "The service account name must be 1 to 63 characters of lowercase letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

variable "cloud_function_name" {
  description = "Name of the HTTP Cloud Function, applied as name on google_cloudfunctions_function.function, named again by the invoker binding on it, published by the cloud_function_name output and read by scripts/deploy.sh as CLOUD_FUNCTION_NAME, so one value names the function for both tools"
  type        = string
  default     = "apartment-finder-probe"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.cloud_function_name))
    error_message = "The function name must be 1 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "cloud_function_source_dir" {
  description = "Directory the function source archive is packaged from, resolved relative to the Terraform module directory and read by data.archive_file.function_source. It must carry the module declaring the entry point google_cloudfunctions_function.function names"
  type        = string
  default     = "../functions/health"

  validation {
    condition     = length(trimspace(var.cloud_function_source_dir)) > 0
    error_message = "The function source directory must not be blank."
  }
}

variable "gke_network" {
  description = "Self-link of a VPC network, retained for deployments that attach the cluster to a network this configuration does not create. The cluster in main.tf attaches to google_compute_network.primary, which is the same VPC the Cloud SQL instance takes its private address on, so the route from the pods to that address is structural rather than asserted across two variables. Expected form: projects/<project>/global/networks/<name>"
  type        = string
  default     = "projects/apartment-finder/global/networks/primary-network"

  validation {
    condition     = can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/networks/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.gke_network))
    error_message = "The network must be a VPC self-link of the form projects/<project>/global/networks/<name>. Blank and malformed values are rejected."
  }
}

variable "gke_subnetwork" {
  description = "Self-link of a subnetwork, retained alongside var.gke_network for deployments that attach the cluster to a subnetwork this configuration does not create. The cluster in main.tf attaches to google_compute_subnetwork.primary. Expected form: projects/<project>/regions/<region>/subnetworks/<name>"
  type        = string
  default     = "projects/apartment-finder/regions/us-central1/subnetworks/primary-subnetwork"

  validation {
    condition     = can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/regions/[a-z]([-a-z0-9]{0,61}[a-z0-9])?/subnetworks/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.gke_subnetwork))
    error_message = "The subnetwork must be a subnetwork self-link of the form projects/<project>/regions/<region>/subnetworks/<name>. Blank and malformed values are rejected."
  }

  validation {
    condition     = try(split("/", var.gke_subnetwork)[3], "") == var.region
    error_message = "The subnetwork must sit in var.region, the region google_container_cluster.primary is created in."
  }
}

variable "database_private_services_access_range_name" {
  description = "Name of a range reserved for private services access, retained as a second spelling of var.private_service_access_range_name. That variable is the one google_compute_global_address.private_services_access is named from and the one google_service_networking_connection.private_services_access publishes; this input is read by no resource"
  type        = string
  default     = "cloudsql-private-services-access"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{0,61}[a-z0-9])$", var.database_private_services_access_range_name))
    error_message = "The range name must be 2 to 63 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "database_private_services_access_prefix_length" {
  description = "Prefix length of the address block reserved for private services access, retained as a second spelling of var.private_service_access_prefix_length. That variable is the one google_compute_global_address.private_services_access takes its prefix_length from; this input is read by no resource"
  type        = number
  default     = 16

  validation {
    condition     = var.database_private_services_access_prefix_length == floor(var.database_private_services_access_prefix_length) && var.database_private_services_access_prefix_length >= 16 && var.database_private_services_access_prefix_length <= 24
    error_message = "The prefix length must be a whole number between 16 and 24. Cloud SQL requires a block of at least /24, and Google recommends /16."
  }
}

variable "gke_master_authorized_networks" {
  description = "CIDR blocks permitted to reach the GKE cluster control plane, applied as the cidr_blocks entries of master_authorized_networks_config on google_container_cluster.primary. The control plane carries a private address only, so every entry must be a private range inside the VPC, and at least one entry is required: it is the network the deployment runs kubectl from"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))

  validation {
    condition     = length(var.gke_master_authorized_networks) > 0
    error_message = "At least one authorized network must be named. The control plane has no public endpoint, so a cluster with no authorized network is reachable by nothing that runs outside its own node subnet -- including the deployment workflow."
  }

  validation {
    condition     = alltrue([for entry in var.gke_master_authorized_networks : can(cidrhost(entry.cidr_block, 0))])
    error_message = "Every authorized network must be a valid CIDR block, such as 10.10.0.0/24."
  }

  validation {
    condition = alltrue([
      for entry in var.gke_master_authorized_networks :
      can(regex("^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.)", trimspace(entry.cidr_block)))
    ])
    error_message = "Every authorized network must be a private range: 10.0.0.0/8, 172.16.0.0/12 or 192.168.0.0/16. A public range cannot reach a control plane that has no public endpoint, so accepting one would record an authorization that does not exist."
  }

  validation {
    condition = alltrue([
      for entry in var.gke_master_authorized_networks :
      tonumber(split("/", trimspace(entry.cidr_block))[1]) >= 8
    ])
    error_message = "Every authorized network must carry a prefix length of at least 8. Ranges broad enough to reach the whole internet are rejected."
  }

  validation {
    condition = alltrue([
      for entry in var.gke_master_authorized_networks :
      length(trimspace(entry.display_name)) > 0
    ])
    error_message = "Every authorized network must carry a non-blank display name."
  }
}

variable "gke_node_service_account_id" {
  description = "Account ID of the dedicated service account the GKE node pool runs as, applied as account_id on the node pool's google_service_account"
  type        = string
  default     = "gke-node-sa"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{4,28}[a-z0-9])$", var.gke_node_service_account_id))
    error_message = "The service account ID must be 6 to 30 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "gke_node_service_account_roles" {
  description = "IAM roles granted to the dedicated GKE node service account, applied as one google_project_iam_member binding per role. The node pool carries the cloud-platform access scope, so this list is what bounds the node identity. Only the node-pool roles named in the validation below are accepted. roles/container.defaultNodeServiceAccount is the base role a GKE node identity requires and is granted by default. roles/storage.objectViewer is not granted and is not accepted: it reads every object in every bucket in the project, including the bucket holding the Cloud Function source archive, and it was present only to resolve a gcr.io image name in a project still served by Container Registry. The release publishes to Artifact Registry, which roles/artifactregistry.reader covers, so the Cloud Storage role bought nothing this deployment uses"
  type        = list(string)
  default = [
    "roles/container.defaultNodeServiceAccount",
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/artifactregistry.reader",
  ]

  validation {
    condition     = length(var.gke_node_service_account_roles) > 0
    error_message = "At least one role must be granted to the node service account."
  }

  validation {
    condition     = contains([for role in var.gke_node_service_account_roles : trimspace(role)], "roles/container.defaultNodeServiceAccount")
    error_message = "The list must contain roles/container.defaultNodeServiceAccount, the base role a GKE node identity requires to register with the cluster and report its status."
  }

  validation {
    condition = alltrue([
      for role in var.gke_node_service_account_roles : contains([
        "roles/container.defaultNodeServiceAccount",
        "roles/logging.logWriter",
        "roles/monitoring.metricWriter",
        "roles/monitoring.viewer",
        "roles/stackdriver.resourceMetadata.writer",
        "roles/artifactregistry.reader",
      ], trimspace(role))
    ])
    error_message = "Only the node-pool roles roles/container.defaultNodeServiceAccount, roles/logging.logWriter, roles/monitoring.metricWriter, roles/monitoring.viewer, roles/stackdriver.resourceMetadata.writer and roles/artifactregistry.reader are accepted. roles/storage.objectViewer is rejected because it reads every object in every bucket in the project, and the images are pulled from Artifact Registry. Broader roles such as roles/editor and roles/owner are rejected."
  }
}

variable "gke_node_oauth_scopes" {
  description = "Access scopes the GKE nodes are created with, applied as node_config.oauth_scopes on google_container_node_pool.primary_nodes. The cloud-platform scope is the scope GKE documents for node pools; the IAM roles in var.gke_node_service_account_roles are what bound the identity's permissions"
  type        = list(string)
  default     = ["https://www.googleapis.com/auth/cloud-platform"]

  validation {
    condition     = length(var.gke_node_oauth_scopes) > 0
    error_message = "At least one access scope must be granted to the node pool."
  }

  validation {
    condition = anytrue([
      for scope in var.gke_node_oauth_scopes : contains([
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/devstorage.read_only",
      ], trimspace(scope))
    ])
    error_message = "The list must contain either the cloud-platform scope or the devstorage.read_only scope. Without one of them the node identity cannot read the image registry the workloads pull from, whatever IAM roles it holds."
  }
}

variable "backend_workload_service_account_id" {
  description = "Account ID of the service account the backend workload impersonates through Workload Identity, applied as account_id on google_service_account.backend_workload. Reading a Secret Manager secret version is granted to this identity and to no other"
  type        = string
  default     = "backend-workload-sa"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{4,28}[a-z0-9])$", var.backend_workload_service_account_id))
    error_message = "The service account ID must be 6 to 30 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "backend_kubernetes_namespace" {
  description = "Kubernetes namespace of the backend workload, retained as a second spelling of var.workload_identity_namespace. That variable is the namespace every Workload Identity principal in this configuration is formed from, including the one granted roles/iam.workloadIdentityUser on google_service_account.backend_workload; this input is read by no resource"
  type        = string
  default     = "default"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.backend_kubernetes_namespace))
    error_message = "The namespace must be a valid Kubernetes DNS label: up to 63 characters of lowercase letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

variable "cloud_function_entry_point" {
  description = "Name of the function inside the deployed source archive that the HTTP trigger calls, applied as entry_point on google_cloudfunctions_function.function and required by scripts/deploy.sh as CLOUD_FUNCTION_ENTRY_POINT so one value names the handler for both tools. The default is not a placeholder: infrastructure/functions/health/main.py, the directory var.cloud_function_source_dir packages, exports exactly this name"
  type        = string
  default     = "hello_world"

  validation {
    condition     = can(regex("^[A-Za-z_][A-Za-z0-9_]*$", var.cloud_function_entry_point))
    error_message = "The Cloud Function entry point must be a Python identifier: a letter or underscore followed by letters, digits or underscores. Blank, dotted and whitespace-bearing values are rejected."
  }
}

variable "gke_dns_endpoint_external_traffic" {
  description = "Whether a caller outside the cluster's VPC may reach the control plane over its DNS-based endpoint, applied as control_plane_endpoints_config.dns_endpoint_config.allow_external_traffic on google_container_cluster.primary. The endpoint authorizes by the IAM permission container.clusters.connect rather than by source address, and the IP-based endpoint stays private either way. It defaults to false so the control plane is reachable from outside the VPC only where a deployment says so: a default of true made every deployment externally reachable unless it opted out, which is the opposite of the posture the private control plane is configured for. Set it to true only for a deployer that runs outside the VPC and cannot be moved inside it"
  type        = bool
  default     = false
}

variable "artifact_registry_repository_id" {
  description = "Repository ID of the Artifact Registry Docker repository the release images are published to, applied as repository_id on google_artifact_registry_repository.containers. Its host is \"<region>-docker.pkg.dev\" and both release paths address it by this name"
  type        = string
  default     = "apartment-finder"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.artifact_registry_repository_id))
    error_message = "The repository ID must be 1 to 63 characters of lowercase letters, digits and hyphens, and must start and end with a letter or digit."
  }
}

variable "artifact_registry_writer_members" {
  description = "IAM principals granted roles/artifactregistry.writer on google_artifact_registry_repository.containers, applied as one google_artifact_registry_repository_iam_member per principal. These are the identities the release automation publishes images with. Expected form: prefixed principal identifiers such as serviceAccount:<name>@<project>.iam.gserviceaccount.com"
  type        = list(string)

  validation {
    condition     = length(var.artifact_registry_writer_members) > 0
    error_message = "At least one principal must be able to publish images, or no release can reach the registry."
  }

  validation {
    condition = alltrue([
      for member in var.artifact_registry_writer_members :
      !contains(["allusers", "allauthenticatedusers"], lower(trimspace(member)))
    ])
    error_message = "Every publisher must name a specific IAM principal. Public principals that grant access to anyone are rejected."
  }

  validation {
    condition = alltrue([
      for member in var.artifact_registry_writer_members :
      can(regex("^(serviceAccount|user|group|principal|principalSet):[^[:space:]]+$", member))
    ])
    error_message = "Every publisher must be a prefixed principal identifier such as serviceAccount:<name>@<project>.iam.gserviceaccount.com. Blank, unprefixed and whitespace-bearing values are rejected."
  }
}

variable "cloud_function_deployment_authorized" {
  description = "Whether google_cloudfunctions_function.function and its invoker binding are created. It defaults to false because the function's runtime pin names a runtime Cloud Functions has decommissioned for create and update, so an apply that reached the resource would fail at the API. It stays false until a release owner decides that conflict, as recorded in docs/security/RESIDUAL_RISK.md"
  type        = bool
  default     = false
}

variable "cloud_function_invoker_member" {
  description = "IAM principal granted roles/cloudfunctions.invoker on google_cloudfunctions_function.function, applied as the sole entry of members on the authoritative google_cloudfunctions_function_iam_binding. Because the binding is authoritative for that role, applying it removes every other member, including any public principal an earlier deployment left behind. Expected form: a prefixed principal identifier such as serviceAccount:<name>@<project>.iam.gserviceaccount.com"
  type        = string

  validation {
    condition     = !contains(["allusers", "allauthenticatedusers"], lower(var.cloud_function_invoker_member))
    error_message = "The Cloud Function invoker must name a specific IAM principal, such as a service account, user, or group member. Public principals that grant access to anyone are rejected."
  }

  validation {
    condition     = can(regex("^(serviceAccount|user|group|principal|principalSet):[^[:space:]]+$", var.cloud_function_invoker_member))
    error_message = "The Cloud Function invoker must be a prefixed principal identifier such as serviceAccount:<name>@<project>.iam.gserviceaccount.com. Blank, unprefixed and whitespace-bearing values are rejected."
  }
}

variable "secret_key" {
  description = "Value stored in the SECRET_KEY Secret Manager secret, applied as secret_data_wo on its google_secret_manager_secret_version and paired with secret_data_wo_version. Supplies the symmetric key the application signs and verifies access tokens with. Ephemeral: the value is available only during the run and is written to neither the plan file nor the state file, so it may be consumed by write-only arguments only"
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = trimspace(var.secret_key) == var.secret_key
    error_message = "The signing key must carry no leading or trailing whitespace, matching the canonical form the application accepts at startup."
  }

  validation {
    # UTF-8 byte length. base64 encodes every three bytes as four
    # characters, so the encoded length less its padding characters
    # carries the byte count the application measures.
    condition     = (length(base64encode(var.secret_key)) / 4 * 3) - length(regexall("=", base64encode(var.secret_key))) >= 32
    error_message = "The signing key must measure at least 32 UTF-8 bytes, matching the floor the application enforces at startup."
  }

  validation {
    # Distinct-character count. split("", s) yields one element per
    # character, so distinct() collapses a repeated unit such as "a" * 32
    # or "Ab" * 16 to fewer entries than the floor admits.
    condition     = length(distinct(split("", var.secret_key))) >= 12
    error_message = "The signing key must carry at least 12 distinct characters, matching the variety floor the application enforces at startup. A key built by repeating one short unit, such as 32 copies of a single character, is rejected."
  }

  validation {
    condition     = !can(regex("(?i)^(change[-_]?me|replace(me|[-_])|your(secret|[-_])|placeholder|insecure)", var.secret_key))
    error_message = "The signing key must not be a placeholder value, matching the placeholder set the application rejects at startup."
  }

  validation {
    # Longest run of one repeated character, matching the run ceiling the
    # application enforces at startup.
    condition     = !can(regex("(.)\\1{3,}", var.secret_key))
    error_message = "The signing key must not repeat one character more than 3 times in a row, matching the run ceiling the application enforces at startup."
  }
}

variable "database_url" {
  description = "Value stored in the DATABASE_URL Secret Manager secret, applied as secret_data_wo on its google_secret_manager_secret_version and paired with secret_data_wo_version. Supplies the SQLAlchemy connection URL the application reaches its database with. Ephemeral: the value is available only during the run and is written to neither the plan file nor the state file, so it may be consumed by write-only arguments only"
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = can(regex("^postgresql(\\+psycopg2)?://[^[:space:]/@]+@?[^[:space:]/]*/[^[:space:]/]+$", trimspace(var.database_url)))
    error_message = "The database URL must use the postgresql:// or postgresql+psycopg2:// scheme and carry both a host and a database name, matching the form the application accepts at startup."
  }

  validation {
    condition     = !can(regex("(?i)(change[-_]?me|replace[-_]|your[-_])", trimspace(var.database_url)))
    error_message = "The database URL must not carry a placeholder segment."
  }
}

variable "zillow_api_key" {
  description = "Value stored in the ZILLOW_API_KEY Secret Manager secret, applied as secret_data_wo on its google_secret_manager_secret_version and paired with secret_data_wo_version. Supplies the listing provider API key the ingestion task sends in a request header. Ephemeral: the value is available only during the run and is written to neither the plan file nor the state file, so it may be consumed by write-only arguments only"
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = length(trimspace(var.zillow_api_key)) >= 8 && !can(regex("(?i)(change[-_]?me|replace[-_]|your[-_]|placeholder)", trimspace(var.zillow_api_key)))
    error_message = "The listing provider API key must be at least 8 characters once trimmed and must not be a placeholder value."
  }
}

variable "paypal_client_secret" {
  description = "Value stored in the PAYPAL_CLIENT_SECRET Secret Manager secret, applied as secret_data_wo on its google_secret_manager_secret_version and paired with secret_data_wo_version. Supplies the PayPal REST client secret the service exchanges for an API access token. Ephemeral: the value is available only during the run and is written to neither the plan file nor the state file, so it may be consumed by write-only arguments only"
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = length(trimspace(var.paypal_client_secret)) >= 8 && !can(regex("(?i)(change[-_]?me|replace[-_]|your[-_]|placeholder)", trimspace(var.paypal_client_secret)))
    error_message = "The PayPal client secret must be at least 8 characters once trimmed and must not be a placeholder value."
  }
}

variable "paypal_webhook_id" {
  description = "Value stored in the PAYPAL_WEBHOOK_ID Secret Manager secret, applied as secret_data_wo on its google_secret_manager_secret_version and paired with secret_data_wo_version. Supplies the PayPal webhook subscription identifier that webhook signature verification requires. Ephemeral: the value is available only during the run and is written to neither the plan file nor the state file, so it may be consumed by write-only arguments only"
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = length(trimspace(var.paypal_webhook_id)) >= 8 && !can(regex("(?i)(change[-_]?me|replace[-_]|your[-_]|placeholder)", trimspace(var.paypal_webhook_id)))
    error_message = "The PayPal webhook identifier must be at least 8 characters once trimmed and must not be a placeholder value."
  }
}

variable "sendgrid_api_key" {
  description = "Value stored in the SENDGRID_API_KEY Secret Manager secret, applied as secret_data_wo on its google_secret_manager_secret_version and paired with secret_data_wo_version. Supplies the SendGrid API key the service sends transactional email with. Ephemeral: the value is available only during the run and is written to neither the plan file nor the state file, so it may be consumed by write-only arguments only"
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = length(trimspace(var.sendgrid_api_key)) >= 8 && !can(regex("(?i)(change[-_]?me|replace[-_]|your[-_]|placeholder)", trimspace(var.sendgrid_api_key)))
    error_message = "The SendGrid API key must be at least 8 characters once trimmed and must not be a placeholder value."
  }
}

variable "admin_seed_password" {
  description = "Value stored in the ADMIN_SEED_PASSWORD Secret Manager secret, applied as secret_data_wo on its google_secret_manager_secret_version and paired with secret_data_wo_version. Read only by infrastructure/kubernetes/70-admin-credential-job.yaml, which is an operator step rather than part of a release, and supplies the credential backend/app/core/admin_provisioning.py stores for the account 0002_seed_single_admin.py grants the administrative role to. Must satisfy the registration password policy, which that module enforces before storing it. Ephemeral: the value is available only during the run and is written to neither the plan file nor the state file, so it may be consumed by write-only arguments only"
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = length(var.admin_seed_password) >= 12 && length(var.admin_seed_password) <= 72 && !can(regex("(?i)(change[-_]?me|replace[-_]|your[-_]|placeholder)", var.admin_seed_password))
    error_message = "The administrator seed password must be 12 to 72 characters and must not be a placeholder value."
  }

  validation {
    condition     = can(regex("[A-Z]", var.admin_seed_password)) && can(regex("[a-z]", var.admin_seed_password)) && can(regex("[0-9]", var.admin_seed_password)) && can(regex("[!@#$%^&*()_+=\\[\\]{};':\"\\\\|,.<>/?-]", var.admin_seed_password))
    error_message = "The administrator seed password must contain an uppercase letter, a lowercase letter, a digit and a special character, which is the policy backend/app/schema/user.py applies to every account."
  }
}

variable "admin_provisioner_service_account_id" {
  description = "Account ID of the service account the administrator provisioning job runs as, applied as account_id on google_service_account.admin_provisioner. Kept separate from backend_service_account_id so that the serving workload cannot read the administrator's credential and this identity cannot read the payment or email credentials"
  type        = string
  default     = "admin-provisioner-sa"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{4,28}[a-z0-9])$", var.admin_provisioner_service_account_id))
    error_message = "The service account ID must be 6 to 30 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "admin_provisioner_kubernetes_service_account" {
  description = "Name of the Kubernetes service account the administrator provisioning job declares. It is the other half of the workload identity member on google_service_account_iam_member.admin_provisioner_workload_identity and must match the service account declared in infrastructure/kubernetes/70-admin-credential-job.yaml"
  type        = string
  default     = "admin-provisioner"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.admin_provisioner_kubernetes_service_account))
    error_message = "The service account name must be 1 to 63 characters of lowercase letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

variable "secret_version_generation" {
  description = "Integer applied as secret_data_wo_version on every google_secret_manager_secret_version. Increment it to make Terraform send the current write-only secret values again; leaving it unchanged leaves the stored versions alone"
  type        = number
  default     = 1
}

variable "database_private_network" {
  description = "Self-link of a VPC network, retained for deployments that attach the database to a network this configuration does not create. The instance in main.tf takes settings.ip_configuration.private_network from google_compute_network.primary, which is the same VPC the cluster's subnetwork is created on, so the route from the pods to the private address is structural rather than asserted across two variables. Expected form: projects/<project>/global/networks/<name>"
  type        = string
  default     = "projects/apartment-finder/global/networks/primary-network"

  validation {
    condition     = can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/networks/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.database_private_network))
    error_message = "The network must be a VPC self-link of the form projects/<project>/global/networks/<name>. Blank and malformed values are rejected."
  }
}

variable "deployer_service_account_id" {
  description = "Account ID of the service account the continuous-deployment workflow impersonates, applied as account_id on google_service_account.deployer"
  type        = string
  default     = "release-deployer"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{4,28}[a-z0-9])$", var.deployer_service_account_id))
    error_message = "The service account ID must be 6 to 30 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "deployer_roles" {
  description = "Project-level IAM roles granted to the deployer service account, applied as one google_project_iam_member binding per role. Image publication is granted on the Artifact Registry repository itself and is not in this list"
  type        = list(string)
  default     = ["roles/container.developer"]

  validation {
    condition     = length(var.deployer_roles) > 0
    error_message = "At least one role must be granted to the deployer service account."
  }

  validation {
    condition = alltrue([
      for role in var.deployer_roles : contains([
        "roles/container.developer",
        "roles/container.viewer",
      ], trimspace(role))
    ])
    error_message = "Only roles/container.developer and roles/container.viewer are accepted. Broader roles such as roles/container.admin, roles/editor and roles/owner are rejected."
  }
}

variable "workload_identity_pool_id" {
  description = "Pool ID of the workload identity pool the release workflow federates through, applied as workload_identity_pool_id on google_iam_workload_identity_pool.github"
  type        = string
  default     = "github-actions"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{2,30}[a-z0-9])$", var.workload_identity_pool_id))
    error_message = "The pool ID must be 4 to 32 characters, start with a lowercase letter, and contain only lowercase letters, digits and hyphens."
  }
}

variable "workload_identity_pool_provider_id" {
  description = "Provider ID of the OIDC provider inside the pool above, applied as workload_identity_pool_provider_id on google_iam_workload_identity_pool_provider.github"
  type        = string
  default     = "github-oidc"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{2,30}[a-z0-9])$", var.workload_identity_pool_provider_id))
    error_message = "The provider ID must be 4 to 32 characters, start with a lowercase letter, and contain only lowercase letters, digits and hyphens."
  }
}

variable "github_repository" {
  description = "The owner/name of the GitHub repository whose workflow may exchange its OIDC token for a credential, applied in the provider's attribute_condition and in the deployer's workloadIdentityUser member. Expected form: owner/name"
  type        = string

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$", var.github_repository))
    error_message = "The repository must be given as owner/name. Blank, unqualified and whitespace-bearing values are rejected."
  }
}

variable "github_deployment_branch" {
  description = "The single branch whose workflow runs may obtain a credential, applied in the provider's attribute_condition as refs/heads/<branch>"
  type        = string
  default     = "main"

  validation {
    condition     = can(regex("^[A-Za-z0-9][A-Za-z0-9._/-]*$", var.github_deployment_branch))
    error_message = "The branch must be a git branch name carrying no whitespace and no leading separator."
  }
}

variable "cloud_function_description" {
  description = "Description applied as description on google_cloudfunctions_function.function"
  type        = string
  default     = "HTTP entry point for the apartment-finder service"

  validation {
    condition     = length(trimspace(var.cloud_function_description)) > 0
    error_message = "The description must not be blank."
  }
}

variable "cloud_function_service_account_id" {
  description = "Account ID of the identity the function runs as, applied as account_id on google_service_account.cloud_function"
  type        = string
  default     = "cloud-function-sa"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{4,28}[a-z0-9])$", var.cloud_function_service_account_id))
    error_message = "The service account ID must be 6 to 30 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "cloud_function_environment_variables" {
  description = "Non-secret configuration applied as environment_variables on google_cloudfunctions_function.function. Secret payloads are read from Secret Manager by the function's own identity, so a name that reads as a credential is rejected here"
  type        = map(string)
  default     = {}

  validation {
    condition = alltrue([
      for name in keys(var.cloud_function_environment_variables) :
      !can(regex("(?i)(secret|password|passwd|token|credential|private_key|api_key)", name))
    ])
    error_message = "A name reading as a credential is rejected. Grant the function access to the secret through var.cloud_function_secret_ids instead."
  }
}

variable "cloud_function_vpc_connector" {
  description = "Self-link or name of the Serverless VPC Access connector the function egresses through, applied as vpc_connector on google_cloudfunctions_function.function. Null omits the connector and its egress setting"
  type        = string
  default     = null

  validation {
    condition     = var.cloud_function_vpc_connector == null || can(regex("^(projects/[^[:space:]/]+/locations/[^[:space:]/]+/connectors/[^[:space:]/]+|[a-z]([-a-z0-9]{0,61}[a-z0-9])?)$", var.cloud_function_vpc_connector))
    error_message = "The connector must be a connector self-link of the form projects/<project>/locations/<region>/connectors/<name>, or a bare connector name."
  }
}

variable "cloud_function_secret_ids" {
  description = "Secret Manager secret IDs the function identity is granted roles/secretmanager.secretAccessor on, applied as one google_secret_manager_secret_iam_member per entry. Empty grants the function no secret access"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for secret_id in var.cloud_function_secret_ids : contains([
        "SECRET_KEY",
        "DATABASE_URL",
        "ZILLOW_API_KEY",
        "PAYPAL_CLIENT_SECRET",
        "PAYPAL_WEBHOOK_ID",
        "SENDGRID_API_KEY",
      ], trimspace(secret_id))
    ])
    error_message = "Only the secret IDs this configuration declares are accepted: SECRET_KEY, DATABASE_URL, ZILLOW_API_KEY, PAYPAL_CLIENT_SECRET, PAYPAL_WEBHOOK_ID and SENDGRID_API_KEY."
  }
}

variable "rate_limit_store_memory_gb" {
  description = "Capacity of the managed rate-limit store in gibibytes, retained as a second spelling of var.rate_limit_store_memory_size_gb. That variable is the one google_redis_instance.rate_limit takes its memory_size_gb from; this input is read by no resource"
  type        = number
  default     = 1

  validation {
    condition     = var.rate_limit_store_memory_gb == floor(var.rate_limit_store_memory_gb) && var.rate_limit_store_memory_gb >= 1 && var.rate_limit_store_memory_gb <= 300
    error_message = "The rate-limit store capacity must be a whole number of gibibytes between 1 and 300. Zero, fractional and negative values are rejected."
  }
}

variable "rate_limit_store_version" {
  description = "Engine version of the managed rate-limit store. google_redis_instance.rate_limit fixes redis_version as a literal, so this input changes no resource and is read by none; the default below states the version the instance is created with, and an operator who needs another one changes that literal"
  type        = string
  default     = "REDIS_6_X"

  validation {
    condition     = contains(["REDIS_6_X", "REDIS_7_0", "REDIS_7_2"], var.rate_limit_store_version)
    error_message = "The rate-limit store version must be REDIS_6_X, REDIS_7_0 or REDIS_7_2."
  }
}

variable "rate_limit_storage_uri" {
  description = "Value stored in the RATE_LIMIT_STORAGE_URI Secret Manager secret, applied as secret_data_wo on its google_secret_manager_secret_version and paired with secret_data_wo_version. Supplies the address, credential and database index the backend keeps its rate-limit counters in, assembled from the host and port google_redis_instance.rate_limit publishes and that instance's AUTH string. Ephemeral: the value is available only during the run and is written to neither the plan file nor the state file, so it may be consumed by write-only arguments only"
  type        = string
  sensitive   = true
  ephemeral   = true

  validation {
    condition     = can(regex("^(async\\+)?(redis(\\+cluster|\\+sentinel|\\+unix)?|rediss|memcached|mongodb(\\+srv)?|etcd)://[^[:space:]]+$", trimspace(var.rate_limit_storage_uri)))
    error_message = "The rate-limit storage URI must name a store shared by every process and carry its address. The in-process schemes bounded-memory, memory and async+memory are rejected here because the application refuses them outside a local run: counters held inside one process admit each limit once per process and are discarded when that process ends."
  }

  validation {
    condition     = !can(regex("(?i)(change[-_]?me|replace[-_]|your[-_]|placeholder|localhost|127\\.0\\.0\\.1)", trimspace(var.rate_limit_storage_uri)))
    error_message = "The rate-limit storage URI must not carry a placeholder segment and must not address this host, which no other process can reach."
  }
}


variable "migration_service_account_id" {
  description = "Account ID of the identity the database migration job assumes, applied as account_id on google_service_account.backend_migrate. It holds read access to the DATABASE_URL secret alone"
  type        = string
  default     = "backend-migrate-sa"

  validation {
    condition     = can(regex("^[a-z]([-a-z0-9]{4,28}[a-z0-9])$", var.migration_service_account_id))
    error_message = "The service account ID must be 6 to 30 characters, start with a lowercase letter, contain only lowercase letters, digits and hyphens, and end with a letter or digit."
  }
}

variable "workload_identity_namespace" {
  description = "Kubernetes namespace holding the service accounts named below, applied inside the workloadIdentityUser member of each google_service_account_iam_member. A binding is scoped to one namespace, so a service account of the same name in another namespace may not assume the identity"
  type        = string
  default     = "apartment-finder"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.workload_identity_namespace))
    error_message = "The namespace must be a valid Kubernetes name: up to 63 characters of lowercase letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

variable "migration_kubernetes_service_account" {
  description = "Name of the Kubernetes service account the migration pod runs as, permitted to act as google_service_account.backend_migrate. The deployment workflow names the same value in its MIGRATION_SERVICE_ACCOUNT environment entry, and the two must agree"
  type        = string
  default     = "backend-migrate"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$", var.migration_kubernetes_service_account))
    error_message = "The service account name must be a valid Kubernetes name: up to 63 characters of lowercase letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

variable "record_sink_degraded_signal" {
  description = "Value the application writes on the signal field of the record it emits when an audit record or a log record could not be written, matched by the filter of google_logging_metric.record_sink_degraded. It must equal backend.app.main.SINK_DEGRADED_SIGNAL"
  type        = string
  default     = "record_sink_degraded"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]*$", var.record_sink_degraded_signal))
    error_message = "The signal must be a lowercase identifier of letters, digits and underscores, as the application emits it."
  }
}

variable "record_sink_degraded_signal_field" {
  description = "Name of the structured field the signal is carried on, used to build the filter of google_logging_metric.record_sink_degraded. It must equal backend.app.core.logging.SIGNAL_FIELD"
  type        = string
  default     = "signal"

  validation {
    condition     = can(regex("^[a-z][a-z0-9_]*$", var.record_sink_degraded_signal_field))
    error_message = "The field must be a lowercase identifier of letters, digits and underscores, as the application emits it."
  }
}

variable "record_sink_degraded_metric_name" {
  description = "Name of the log-based metric counting the degradation signal, applied as name on google_logging_metric.record_sink_degraded and referenced by the alert policy's filter"
  type        = string
  default     = "record_sink_degraded"

  validation {
    condition     = can(regex("^[A-Za-z0-9_/.-]{1,100}$", var.record_sink_degraded_metric_name))
    error_message = "The metric name must be 1 to 100 characters of letters, digits, underscores, slashes, dots and hyphens."
  }
}

variable "alert_notification_channels" {
  description = "Notification channel identifiers the degradation alert is delivered to, applied as notification_channels on google_monitoring_alert_policy.record_sink_degraded. An empty list records incidents without notifying anyone, which is a configuration to correct rather than a default to rely on. Expected form: projects/<project>/notificationChannels/<id>"
  type        = list(string)
  default     = []

  validation {
    condition = alltrue([
      for channel in var.alert_notification_channels :
      can(regex("^projects/[^/]+/notificationChannels/[0-9]+$", trimspace(channel)))
    ])
    error_message = "Every notification channel must be of the form projects/<project>/notificationChannels/<id>."
  }
}

variable "log_retention_days" {
  description = "Days of retention on the _Default log bucket, applied as retention_days on google_logging_project_bucket_config.default. It bounds how far back the records an alert points at can be read"
  type        = number
  default     = 30

  validation {
    condition     = var.log_retention_days >= 30 && var.log_retention_days <= 3650
    error_message = "Retention must be between 30 and 3650 days. A shorter window discards the records an incident is investigated from."
  }
}

variable "cloud_function_vpc_connector_egress_settings" {
  description = "Which of the function's egress traverses the connector, applied as vpc_connector_egress_settings on google_cloudfunctions_function.function. PRIVATE_RANGES_ONLY sends private-address traffic through it and leaves public traffic direct; ALL_TRAFFIC sends everything through it"
  type        = string
  default     = "PRIVATE_RANGES_ONLY"

  validation {
    condition     = contains(["PRIVATE_RANGES_ONLY", "ALL_TRAFFIC"], var.cloud_function_vpc_connector_egress_settings)
    error_message = "Egress settings must be PRIVATE_RANGES_ONLY or ALL_TRAFFIC."
  }
}

variable "backend_workload_namespace" {
  description = "Kubernetes namespace of the service account that impersonates google_service_account.backend_workload, retained as a second spelling of var.workload_identity_namespace. That variable is the namespace half of local.backend_workload_principal, which google_service_account_iam_member.backend_workload_identity binds; this input is read by no resource"
  type        = string
  default     = "default"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.backend_workload_namespace))
    error_message = "The Kubernetes namespace must be 1 to 63 characters of lower-case letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

variable "backend_workload_service_account" {
  description = "Name of the Kubernetes service account that impersonates google_service_account.backend_workload, retained as a second spelling of var.backend_kubernetes_service_account. That variable is the account half of local.backend_workload_principal, which google_service_account_iam_member.backend_workload_identity binds; this input is read by no resource. The Kubernetes object that carries the account name must carry an iam.gke.io/gcp-service-account annotation naming the email outputs.tf publishes as backend_runtime_service_account_email"
  type        = string
  default     = "apartment-finder-backend"

  validation {
    condition     = can(regex("^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", var.backend_workload_service_account))
    error_message = "The Kubernetes service account name must be 1 to 63 characters of lower-case letters, digits and hyphens, starting and ending with a letter or digit."
  }
}

variable "cloud_function_ingress_settings" {
  description = "Network boundary applied as ingress_settings on google_cloudfunctions_function.function. ALLOW_INTERNAL_ONLY admits callers inside the VPC and the project; ALLOW_INTERNAL_AND_GCLB additionally admits the external HTTP load balancer. ALLOW_ALL is rejected by the validation below"
  type        = string
  default     = "ALLOW_INTERNAL_ONLY"

  validation {
    condition     = contains(["ALLOW_INTERNAL_ONLY", "ALLOW_INTERNAL_AND_GCLB"], var.cloud_function_ingress_settings)
    error_message = "The Cloud Function ingress setting must be ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB. ALLOW_ALL, which admits any caller on the internet at the network layer, is rejected."
  }
}
