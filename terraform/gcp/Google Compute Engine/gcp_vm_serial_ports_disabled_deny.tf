# Configure the Google Provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a GCP VM instance with serial ports enabled (non-compliant)
resource "google_compute_instance" "fail_instance" {
  name         = "fail-instance"
  machine_type = "e2-medium"
  zone         = "us-central1-a"

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-10"
    }
  }

  network_interface {
    network = "default"
  }

  # Explicitly enabling serial ports (non-compliant configuration)
  metadata = {
    serial-port-enable = "TRUE"
  }

  labels = {
    environment = "test"
  }
}
