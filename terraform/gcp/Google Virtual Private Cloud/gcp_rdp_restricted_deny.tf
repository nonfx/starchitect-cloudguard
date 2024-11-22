provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create firewall rule with unrestricted RDP access (non-compliant)
resource "google_compute_firewall" "fail_rule" {
  provider = google.fail_google
  name    = "fail-rdp-rule"
  network = "default"
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["0.0.0.0/0"]  # Non-compliant: Allows RDP from anywhere
}
