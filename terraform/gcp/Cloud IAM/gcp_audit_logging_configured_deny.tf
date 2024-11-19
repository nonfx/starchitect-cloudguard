provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create audit config missing required log types
resource "google_project_iam_audit_config" "fail_audit_config" {
  provider = google.fail_google
  project  = "my-project-id"
  service  = "allServices"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  
  # Missing DATA_READ and DATA_WRITE log types
}
