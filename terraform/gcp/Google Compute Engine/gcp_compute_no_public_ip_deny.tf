provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Instance with public IP address - should fail
resource "google_compute_instance" "fail_instance" {
  name         = "fail-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  # Network interface with public IP configuration
  network_interface {
    network = "default"
    access_config {
      # Empty block creates an ephemeral public IP
    }
  }
}
