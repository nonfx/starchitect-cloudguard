provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create API key without restrictions
resource "google_apikeys_key" "fail_key" {
  provider = google.fail_google
  name     = "fail-api-key"
  project  = "my-project-id"
  display_name = "Test API Key"

  # No API restrictions configured
}
