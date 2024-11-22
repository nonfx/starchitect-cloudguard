# Configure the Google Provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a GCP instance without Shielded VM
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

  # Shielded VM configuration is missing
}
