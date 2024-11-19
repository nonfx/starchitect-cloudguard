provider "google" {
  project = "my-project"
  region  = "us-central1"
}

# Create storage bucket without retention policy - This will fail the policy check
resource "google_storage_bucket" "fail_bucket" {
  name     = "fail-log-bucket"
  location = "US"
  
  # Enable uniform bucket-level access for security
  uniform_bucket_level_access = true
  
  # Enable versioning for data protection
  versioning {
    enabled = true
  }
  
  # Missing retention policy configuration makes this non-compliant
  
  labels = {
    environment = "test"
  }
}