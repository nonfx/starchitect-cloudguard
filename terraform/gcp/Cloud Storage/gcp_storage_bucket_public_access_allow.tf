provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create a storage bucket with proper access controls
resource "google_storage_bucket" "pass_bucket" {
  provider = google.pass_google
  name     = "pass-private-bucket"
  location = "US"
  
  uniform_bucket_level_access = true
}

# Add restricted access through IAM binding
resource "google_storage_bucket_iam_binding" "pass_binding" {
  provider = google.pass_google
  bucket   = google_storage_bucket.pass_bucket.name
  role     = "roles/storage.objectViewer"
  members  = [
    "user:secure-user@example.com",
    "serviceAccount:my-service@my-project.iam.gserviceaccount.com"
  ]
}

# Add specific user access through IAM member
resource "google_storage_bucket_iam_member" "pass_member" {
  provider = google.pass_google
  bucket   = google_storage_bucket.pass_bucket.name
  role     = "roles/storage.objectViewer"
  member   = "group:secure-group@example.com"
}
