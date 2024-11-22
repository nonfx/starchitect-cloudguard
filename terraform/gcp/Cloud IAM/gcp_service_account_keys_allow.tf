provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create service account without user-managed keys
resource "google_service_account" "pass_sa" {
  provider = google.pass_google
  account_id   = "pass-service-account"
  display_name = "Pass Service Account"
  description  = "Service account using only GCP-managed keys"
}
