provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Enable Cloud Asset Inventory API with proper configuration
resource "google_project_service" "pass_service" {
  project = "my-project-id"
  service = "cloudasset.googleapis.com"
  
  disable_dependent_services = false
  disable_on_destroy = false
}