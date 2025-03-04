provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create firewall rule with restricted RDP access (compliant)
resource "google_compute_firewall" "pass_rule" {
  provider = google.pass_google
  name    = "pass-rdp-rule"
  network = "default"
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["3389"]
  }

  source_ranges = ["10.0.0.0/8"]  # Compliant: Restricts RDP to internal network
}
