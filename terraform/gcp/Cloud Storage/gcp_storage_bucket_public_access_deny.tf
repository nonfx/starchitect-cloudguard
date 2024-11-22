provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create a storage bucket with public access
resource "google_storage_bucket" "fail_bucket" {
  provider = google.fail_google
  name     = "fail-public-bucket"
  location = "US"
}

# Add public access through IAM binding
resource "google_storage_bucket_iam_binding" "fail_binding" {
  provider = google.fail_google
  bucket   = google_storage_bucket.fail_bucket.name
  role     = "roles/storage.objectViewer"
  members  = ["allUsers"] # This makes it public
}

# Add another public access through IAM member
resource "google_storage_bucket_iam_member" "fail_member" {
  provider = google.fail_google
  bucket   = google_storage_bucket.fail_bucket.name
  role     = "roles/storage.objectViewer"
  member   = "allAuthenticatedUsers" # This also makes it public
}
