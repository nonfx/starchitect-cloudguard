# Configure GCP provider
provider "google" {
  project = "my-project"
  region  = "us-central1"
}

# Create a storage bucket with uniform bucket-level access (compliant)
resource "google_storage_bucket" "compliant_bucket" {
  name          = "compliant-bucket"
  location      = "US"
  force_destroy = true

  # Enable uniform bucket-level access for consistent IAM permissions
  uniform_bucket_level_access = true
}
