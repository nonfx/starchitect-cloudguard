# Configure Google Cloud provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a disk without CSEK encryption (non-compliant)
resource "google_compute_disk" "fail_disk" {
  name  = "non-compliant-disk"
  zone  = "us-central1-a"
  size  = 100
  type  = "pd-standard"

  # Missing disk_encryption_key block makes this non-compliant

  labels = {
    environment = "production"
    purpose     = "testing"
  }
}
