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

variable "database_private_network" {
  description = "Self-link of the existing VPC network the Cloud SQL instance attaches to, applied as settings.ip_configuration.private_network on google_sql_database_instance.main. Expected form: projects/<project>/global/networks/<name>"
  type        = string

  validation {
    condition     = can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/networks/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.database_private_network))
    error_message = "The network must be a VPC self-link of the form projects/<project>/global/networks/<name>. Blank and malformed values are rejected."
  }
}

variable "gke_master_authorized_networks" {
  description = "CIDR blocks permitted to reach the GKE cluster control plane, applied as the cidr_blocks entries of master_authorized_networks_config on google_container_cluster.primary. An empty list authorizes no external network"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []

  validation {
    condition     = alltrue([for entry in var.gke_master_authorized_networks : can(cidrhost(entry.cidr_block, 0))])
    error_message = "Every authorized network must be a valid CIDR block, such as 203.0.113.0/24."
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
  description = "IAM roles granted to the dedicated GKE node service account, applied as one google_project_iam_member binding per role. Only the node-pool roles named in the validation below are accepted"
  type        = list(string)
  default = [
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/artifactregistry.reader",
  ]

  validation {
    condition     = length(var.gke_node_service_account_roles) > 0
    error_message = "At least one role must be granted to the node service account."
  }

  validation {
    condition = alltrue([
      for role in var.gke_node_service_account_roles : contains([
        "roles/logging.logWriter",
        "roles/monitoring.metricWriter",
        "roles/monitoring.viewer",
        "roles/stackdriver.resourceMetadata.writer",
        "roles/artifactregistry.reader",
        "roles/storage.objectViewer",
      ], trimspace(role))
    ])
    error_message = "Only the node-pool roles roles/logging.logWriter, roles/monitoring.metricWriter, roles/monitoring.viewer, roles/stackdriver.resourceMetadata.writer, roles/artifactregistry.reader and roles/storage.objectViewer are accepted. Broader roles such as roles/editor and roles/owner are rejected."
  }
}

variable "cloud_function_invoker_member" {
  description = "IAM principal granted roles/cloudfunctions.invoker on google_cloudfunctions_function.function, applied as member on the matching google_cloudfunctions_function_iam_member. Expected form: a prefixed principal identifier such as serviceAccount:<name>@<project>.iam.gserviceaccount.com"
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
    condition     = !can(regex("(?i)^(change[-_]?me|replace(me|[-_])|your(secret|[-_])|placeholder|insecure)", var.secret_key))
    error_message = "The signing key must not be a placeholder value, matching the placeholder set the application rejects at startup."
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

variable "secret_version_generation" {
  description = "Integer applied as secret_data_wo_version on every google_secret_manager_secret_version. Increment it to make Terraform send the current write-only secret values again; leaving it unchanged leaves the stored versions alone"
  type        = number
  default     = 1
}
