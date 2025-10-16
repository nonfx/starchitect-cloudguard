provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create firewall rule with unrestricted SSH access (non-compliant)
resource "google_compute_firewall" "fail_rule" {
  name    = "fail-ssh-rule"
  network = "default"
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"]  # Non-compliant: Allows SSH from anywhere
}
