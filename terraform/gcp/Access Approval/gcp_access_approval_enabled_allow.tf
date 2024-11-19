provider "google" {
  alias = "pass_aws"
  project = "my-project-id"
  region  = "us-central1"
}

# Create properly configured access approval settings
resource "google_project_access_approval_settings" "pass_settings" {
  provider = google.pass_aws
  project_id = "my-project-id"
  
  enrolled_services {
    cloud_product = "all"
    enrollment_level = "BLOCK_ALL"
  }
  
  notification_emails = ["security@example.com"]
}