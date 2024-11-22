provider "google" {
  alias = "fail_gcp"
  project = "my-project"
  region  = "us-central1"
}

resource "google_dns_managed_zone" "fail_zone" {
  provider = google.fail_gcp
  name        = "fail-example-zone"
  dns_name    = "fail-example.com."
  description = "Example DNS zone with RSASHA1"

  dnssec_config {
    state = "on"
    default_key_specs {
      algorithm = "rsasha1"  # Non-compliant: Using RSASHA1
      key_length = 2048
      key_type   = "zoneSigning"
      kind       = "dnsKeySpec"
    }
  }
}