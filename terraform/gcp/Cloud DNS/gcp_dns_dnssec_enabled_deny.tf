provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create a DNS zone without DNSSEC enabled
resource "google_dns_managed_zone" "fail_zone" {
  provider = google.fail_google
  name        = "fail-example-zone"
  dns_name    = "fail-example.com."
  description = "Example DNS zone without DNSSEC"
  visibility  = "public"
  
  # DNSSEC configuration missing or disabled
  dnssec_config {
    state = "off"
  }
}