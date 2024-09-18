output "kubernetes_cluster_endpoint" {
  description = "The endpoint for the Kubernetes cluster"
  value       = google_container_cluster.primary.endpoint
}

output "database_instance_connection_name" {
  description = "The connection name of the Cloud SQL database instance"
  value       = google_sql_database_instance.main.connection_name
}

output "storage_bucket_urls" {
  description = "The URLs of the created storage buckets"
  value = {
    raw_data     = google_storage_bucket.raw_data.url
    processed_data = google_storage_bucket.processed_data.url
    artifacts    = google_storage_bucket.artifacts.url
  }
}

output "pubsub_topic_names" {
  description = "The names of the created Pub/Sub topics"
  value = {
    raw_data     = google_pubsub_topic.raw_data.name
    processed_data = google_pubsub_topic.processed_data.name
  }
}

output "cloud_functions_urls" {
  description = "The URLs of the deployed Cloud Functions"
  value = {
    data_processor = google_cloudfunctions_function.data_processor.https_trigger_url
    data_analyzer  = google_cloudfunctions_function.data_analyzer.https_trigger_url
  }
}

# HUMAN ASSISTANCE NEEDED
# The following outputs may need to be adjusted based on the actual resource names and configurations in your Terraform setup.
# Please verify and modify as necessary to match your specific infrastructure.