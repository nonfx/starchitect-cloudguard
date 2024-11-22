provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create API key with specific API restrictions
resource "google_apikeys_key" "pass_key" {
  provider = google.pass_google
  name     = "pass-api-key"
  project  = "my-project-id"
  display_name = "Test API Key"

  restrictions {
    api_targets {
      service = "translate.googleapis.com"
      methods = ["translate.text.translate"]
    }
    
    api_targets {
      service = "storage.googleapis.com"
      methods = ["storage.objects.get", "storage.objects.list"]
    }
  }
}
