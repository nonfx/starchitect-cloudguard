provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create default network (non-compliant)
resource "google_compute_network" "fail_network" {
  provider = google.fail_google
  name = "default"
  auto_create_subnetworks = true
  
  description = "Default network for the project"
}
