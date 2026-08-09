output "kubernetes_cluster_endpoint" {
  description = "The endpoint for the Kubernetes cluster"
  value       = google_container_cluster.primary.endpoint
}

output "database_instance_connection_name" {
  description = "The connection name of the Cloud SQL database instance"
  value       = google_sql_database_instance.main.connection_name
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

output "cloud_functions_urls" {
  description = "The HTTPS trigger URL of the deployed Cloud Function, keyed by resource name"
  value = {
    function = google_cloudfunctions_function.function.https_trigger_url
  }
}