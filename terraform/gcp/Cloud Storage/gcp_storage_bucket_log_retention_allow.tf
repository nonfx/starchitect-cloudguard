provider "google" {
  project = "my-project"
  region  = "us-central1"
}

# Create storage bucket with proper retention policy and bucket lock - This will pass the policy check
resource "google_storage_bucket" "pass_bucket" {
  name     = "pass-log-bucket"
  location = "US"
  
  # Enable uniform bucket-level access for security
  uniform_bucket_level_access = true
  
  # Enable versioning for data protection
  versioning {
    enabled = true
  }
  
  # Configure retention policy with bucket lock
  retention_policy {
    is_locked = true
    retention_period = 2592000  # 30 days in seconds
  }
  
  # Configure bucket logging
  logging {
    log_bucket = "bucket-logs"
  }
  
  labels = {
    environment = "production"
  }
}