# Configure GCP provider
provider "google" {
  project = "my-project"
  region  = "us-central1"
}

# Create a storage bucket without uniform bucket-level access (non-compliant)
resource "google_storage_bucket" "non_compliant_bucket" {
  name          = "non-compliant-bucket"
  location      = "US"
  force_destroy = true
  
  # Uniform bucket-level access is disabled by default
  uniform_bucket_level_access = false
}
