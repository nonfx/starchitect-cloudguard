provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create firewall rule with restricted SSH access (compliant)
resource "google_compute_firewall" "pass_rule" {
  name    = "pass-ssh-rule"
  network = "default"
  direction = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["10.0.0.0/8"]  # Compliant: Restricts SSH to internal network
}
