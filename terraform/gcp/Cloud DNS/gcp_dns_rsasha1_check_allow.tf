provider "google" {
  alias = "pass_gcp"
  project = "my-project"
  region  = "us-central1"
}

resource "google_dns_managed_zone" "pass_zone" {
  provider = google.pass_gcp
  name        = "pass-example-zone"
  dns_name    = "pass-example.com."
  description = "Example DNS zone with secure algorithm"

  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm = "rsasha256"  # Compliant: Using RSASHA256
      key_length = 2048
      key_type   = "zoneSigning"
      kind       = "dnsKeySpec"
    }
    default_key_specs {
      algorithm = "rsasha256"
      key_length = 2048
      key_type   = "keySigning"
      kind       = "dnsKeySpec"
    }
  }
}