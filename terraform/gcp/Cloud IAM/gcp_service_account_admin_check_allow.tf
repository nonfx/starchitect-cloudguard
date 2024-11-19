# Configure the Google Provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a service account with limited privileges (compliant)
resource "google_service_account" "viewer_sa" {
  account_id   = "viewer-service-account"
  display_name = "Viewer Service Account"
}

# Assign viewer role to service account using member binding (compliant)
resource "google_project_iam_member" "viewer_member" {
  project = "my-project-id"
  role    = "roles/viewer"
  member  = "serviceAccount:${google_service_account.viewer_sa.email}"
}

# Assign storage viewer role to service account using binding (compliant)
resource "google_project_iam_binding" "storage_viewer_binding" {
  project = "my-project-id"
  role    = "roles/storage.objectViewer"
  members = [
    "serviceAccount:${google_service_account.viewer_sa.email}"
  ]
}
