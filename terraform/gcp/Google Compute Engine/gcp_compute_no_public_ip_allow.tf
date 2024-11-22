provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Instance without public IP address - should pass
resource "google_compute_instance" "pass_instance" {
  name         = "pass-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  # Network interface without public IP configuration
  network_interface {
    network = "default"
    # No access_config block means no public IP
  }
}
