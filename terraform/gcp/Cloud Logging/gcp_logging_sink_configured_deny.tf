# Configure Google Cloud provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create storage bucket for logs
resource "google_storage_bucket" "fail_log_bucket" {
  name     = "fail-log-bucket-example"
  location = "US"
}

# Create logging sink with filter (non-compliant)
resource "google_logging_project_sink" "fail_sink" {
  name     = "fail-sink-example"
  
  # Non-compliant: Has filter which limits log entries
  filter   = "resource.type = gce_instance"
  
  # Destination for the logs
  destination = "storage.googleapis.com/${google_storage_bucket.fail_log_bucket.name}"

  unique_writer_identity = true
}