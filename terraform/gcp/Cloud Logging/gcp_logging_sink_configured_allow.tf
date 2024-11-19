# Configure Google Cloud provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create storage bucket for logs
resource "google_storage_bucket" "pass_log_bucket" {
  name     = "pass-log-bucket-example"
  location = "US"
}

# Create logging sink without filter (compliant)
resource "google_logging_project_sink" "pass_sink" {
  name     = "pass-sink-example"
  
  # Compliant: No filter specified, captures all log entries
  destination = "storage.googleapis.com/${google_storage_bucket.pass_log_bucket.name}"

  unique_writer_identity = true
}