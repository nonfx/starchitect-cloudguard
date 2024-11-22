provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create audit config with all required log types
resource "google_project_iam_audit_config" "pass_audit_config" {
  provider = google.pass_google
  project  = "my-project-id"
  service  = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }

  audit_log_config {
    log_type = "DATA_READ"
  }

  audit_log_config {
    log_type = "DATA_WRITE"
  }
}
