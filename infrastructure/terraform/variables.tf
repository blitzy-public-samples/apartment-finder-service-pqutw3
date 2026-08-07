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
}

variable "database_private_network" {
  description = "Self-link of the existing VPC network the Cloud SQL instance attaches to, applied as settings.ip_configuration.private_network on google_sql_database_instance.main. Expected form: projects/<project>/global/networks/<name>"
  type        = string
}

variable "gke_master_authorized_networks" {
  description = "CIDR blocks permitted to reach the GKE cluster control plane, applied as the cidr_blocks entries of master_authorized_networks_config on google_container_cluster.primary. An empty list authorizes no external network"
  type = list(object({
    cidr_block   = string
    display_name = string
  }))
  default = []
}

variable "gke_node_service_account_id" {
  description = "Account ID of the dedicated service account the GKE node pool runs as, applied as account_id on the node pool's google_service_account"
  type        = string
  default     = "gke-node-sa"
}

variable "gke_node_service_account_roles" {
  description = "IAM roles granted to the dedicated GKE node service account, applied as one google_project_iam_member binding per role"
  type        = list(string)
  default = [
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/artifactregistry.reader",
  ]
}

variable "cloud_function_invoker_member" {
  description = "IAM principal granted roles/cloudfunctions.invoker on google_cloudfunctions_function.function, applied as member on the matching google_cloudfunctions_function_iam_member. Expected form: a prefixed principal identifier such as serviceAccount:<name>@<project>.iam.gserviceaccount.com"
  type        = string

  validation {
    condition     = !contains(["allusers", "allauthenticatedusers"], lower(var.cloud_function_invoker_member))
    error_message = "The Cloud Function invoker must name a specific IAM principal, such as a service account, user, or group member. Public principals that grant access to anyone are rejected."
  }
}

variable "secret_key" {
  description = "Value stored in the SECRET_KEY Secret Manager secret, applied as secret_data on its google_secret_manager_secret_version. Supplies the symmetric key the application signs and verifies access tokens with"
  type        = string
  sensitive   = true
}

variable "database_url" {
  description = "Value stored in the DATABASE_URL Secret Manager secret, applied as secret_data on its google_secret_manager_secret_version. Supplies the SQLAlchemy connection URL the application reaches its database with"
  type        = string
  sensitive   = true
}

variable "zillow_api_key" {
  description = "Value stored in the ZILLOW_API_KEY Secret Manager secret, applied as secret_data on its google_secret_manager_secret_version. Supplies the listing provider API key the ingestion task sends in a request header"
  type        = string
  sensitive   = true
}

variable "paypal_client_secret" {
  description = "Value stored in the PAYPAL_CLIENT_SECRET Secret Manager secret, applied as secret_data on its google_secret_manager_secret_version. Supplies the PayPal REST client secret the service exchanges for an API access token"
  type        = string
  sensitive   = true
}

variable "paypal_webhook_id" {
  description = "Value stored in the PAYPAL_WEBHOOK_ID Secret Manager secret, applied as secret_data on its google_secret_manager_secret_version. Supplies the PayPal webhook subscription identifier that webhook signature verification requires"
  type        = string
  sensitive   = true
}

variable "sendgrid_api_key" {
  description = "Value stored in the SENDGRID_API_KEY Secret Manager secret, applied as secret_data on its google_secret_manager_secret_version. Supplies the SendGrid API key the service sends transactional email with"
  type        = string
  sensitive   = true
}