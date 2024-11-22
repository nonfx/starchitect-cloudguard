# Configure Google Cloud provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a disk with CSEK encryption (compliant)
resource "google_compute_disk" "pass_disk" {
  name  = "compliant-disk"
  zone  = "us-central1-a"
  size  = 100
  type  = "pd-standard"

  # Configure CSEK encryption
  disk_encryption_key {
    raw_key = "SGVsbG8gZnJvbSBHb29nbGUgQ2xvdWQgUGxhdGZvcm0="  # Base64 encoded encryption key
  }

  labels = {
    environment = "production"
    purpose     = "application"
  }
}
