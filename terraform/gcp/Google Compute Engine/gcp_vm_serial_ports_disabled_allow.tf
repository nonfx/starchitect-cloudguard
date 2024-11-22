# Configure the Google Provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a GCP VM instance with serial ports disabled (compliant)
resource "google_compute_instance" "pass_instance" {
  name         = "pass-instance"
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

  # Serial ports are disabled by default (compliant configuration)
  metadata = {
    environment = "production"
  }

  labels = {
    environment = "production"
  }
}
