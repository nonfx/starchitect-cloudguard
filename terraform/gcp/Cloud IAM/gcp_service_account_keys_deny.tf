provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create service account
resource "google_service_account" "fail_sa" {
  provider = google.fail_google
  account_id   = "fail-service-account"
  display_name = "Fail Service Account"
}

# Create user-managed key (non-compliant)
resource "google_service_account_key" "fail_key" {
  provider = google.fail_google
  service_account_id = google_service_account.fail_sa.name
  public_key_type    = "TYPE_X509_PEM_FILE"
  private_key_type   = "TYPE_GOOGLE_CREDENTIALS_FILE"
}
