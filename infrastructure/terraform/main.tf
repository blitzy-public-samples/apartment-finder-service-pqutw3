# Main Terraform configuration file for provisioning Google Cloud resources

# Provider configuration for Google Cloud
provider "google" {
  project = var.project_id
  region  = var.region
}

# Resource definitions for Google Kubernetes Engine cluster
resource "google_container_cluster" "primary" {
  name     = "primary-cluster"
  location = var.region

  remove_default_node_pool = true
  initial_node_count       = 1

  master_auth {
    client_certificate_config {
      issue_client_certificate = false
    }
  }

  # The control plane endpoint and the nodes carry private addresses only.
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
  }

  # Only the CIDR blocks listed in var.gke_master_authorized_networks may
  # reach the control plane. An empty list authorizes no external network.
  master_authorized_networks_config {
    dynamic "cidr_blocks" {
      for_each = var.gke_master_authorized_networks

      content {
        cidr_block   = cidr_blocks.value.cidr_block
        display_name = cidr_blocks.value.display_name
      }
    }
  }

  # VPC-native addressing, with GKE assigning the pod and service ranges.
  ip_allocation_policy {}
}

resource "google_container_node_pool" "primary_nodes" {
  name       = "primary-node-pool"
  location   = var.region
  cluster    = google_container_cluster.primary.name
  node_count = var.gke_num_nodes

  node_config {
    # The nodes run as the dedicated account defined below.
    service_account = google_service_account.gke_nodes.email

    oauth_scopes = [
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
    ]

    labels = {
      env = var.project_id
    }

    machine_type = "n1-standard-1"
    tags         = ["gke-node", "${var.project_id}-gke"]
    metadata = {
      disable-legacy-endpoints = "true"
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

# Resource definitions for Google Cloud SQL instance
resource "google_sql_database_instance" "main" {
  name             = "main-instance"
  database_version = "POSTGRES_13"
  region           = var.region

  settings {
    tier = "db-f1-micro"

    # The instance is reachable over the VPC in var.database_private_network
    # only, with no public IPv4 address, and accepts encrypted connections
    # only.
    ip_configuration {
      ipv4_enabled    = false
      private_network = var.database_private_network
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

# Resource definitions for Google Cloud Functions
resource "google_cloudfunctions_function" "function" {
  name        = "function-test"
  description = "My function"
  runtime     = "python39"

  available_memory_mb   = 128
  source_archive_bucket = google_storage_bucket.static_assets.name
  source_archive_object = "function-source.zip"
  trigger_http          = true
  entry_point           = "hello_world"
}

# Invocation of the function above is limited to the single principal named
# by var.cloud_function_invoker_member, whose own validation rejects the
# public principals.
resource "google_cloudfunctions_function_iam_member" "invoker" {
  project        = google_cloudfunctions_function.function.project
  region         = google_cloudfunctions_function.function.region
  cloud_function = google_cloudfunctions_function.function.name

  role   = "roles/cloudfunctions.invoker"
  member = var.cloud_function_invoker_member
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

# HUMAN ASSISTANCE NEEDED
# The following aspects may need further configuration or customization:
# 1. Adjust the GKE cluster and node pool configurations based on specific requirements
# 2. Implement more detailed configurations for Cloud Functions (e.g., environment variables, VPC connector)
# 3. Add any additional resources that may be required for the specific use case