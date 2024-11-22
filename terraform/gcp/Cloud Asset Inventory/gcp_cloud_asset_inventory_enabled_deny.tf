provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create Cloud Asset Inventory API service with incorrect configuration
resource "google_project_service" "fail_service" {
  project = "my-project-id"
  service = "cloudasset.googleapis.com"
  
  disable_dependent_services = true
  disable_on_destroy = true
}