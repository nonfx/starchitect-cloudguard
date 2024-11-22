provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create a DNS zone with DNSSEC enabled
resource "google_dns_managed_zone" "pass_zone" {
  provider = google.pass_google
  name        = "pass-example-zone"
  dns_name    = "pass-example.com."
  description = "Example DNS zone with DNSSEC enabled"
  visibility  = "public"
  
  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 2048
      key_type   = "keySigning"
      kind       = "dns#dnsKeySpec"
    }
    default_key_specs {
      algorithm  = "rsasha256"
      key_length = 1024
      key_type   = "zoneSigning"
      kind       = "dns#dnsKeySpec"
    }
  }
}