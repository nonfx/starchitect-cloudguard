provider "google" {
  alias = "fail_aws"
  project = "my-project-id"
  region  = "us-central1"
}

# Create access approval settings with incorrect configuration
resource "google_project_access_approval_settings" "fail_settings" {
  provider = google.fail_aws
  project_id = "my-project-id"
  
  enrolled_services {
    cloud_product = "compute.googleapis.com"
    enrollment_level = "NO_BLOCK"
  }
  
  notification_emails = []
}