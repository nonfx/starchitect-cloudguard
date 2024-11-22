# Configure the Google Provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a service account with admin privileges (non-compliant)
resource "google_service_account" "admin_sa" {
  account_id   = "admin-service-account"
  display_name = "Admin Service Account"
}

# Assign admin role to service account using member binding (non-compliant)
resource "google_project_iam_member" "admin_member" {
  project = "my-project-id"
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.admin_sa.email}"
}

# Assign admin role to service account using binding (non-compliant)
resource "google_project_iam_binding" "admin_binding" {
  project = "my-project-id"
  role    = "roles/resourcemanager.projectIamAdmin"
  members = [
    "serviceAccount:${google_service_account.admin_sa.email}"
  ]
}
