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

variable "db_app_user" {
  description = "The name of the application database role"
  type        = string
  default     = "app_user"
}

# SEC-12: the value arrives through the environment or a gitignored variable
# file, never on the command line, so it stays out of the process arguments
# any local user can read and out of shell history (CWE-214, CWE-532)
variable "db_app_password" {
  description = "The password for the application database role. Supply it through the TF_VAR_db_app_password environment variable, or through a gitignored *.tfvars file passed with -var-file, or from a secret manager via an ephemeral input. Never pass it on the command line: -var puts the value in the process arguments, which any local user can read, and in shell history. An ephemeral value is never written to state or to a plan file."
  type        = string
  sensitive   = true
  ephemeral   = true
}

variable "db_app_password_version" {
  description = "Increment to rotate the application database password. Terraform reapplies password_wo only when this value changes."
  type        = number
  default     = 1
}