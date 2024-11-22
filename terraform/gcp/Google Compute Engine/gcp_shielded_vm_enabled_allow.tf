# Configure the Google Provider
provider "google" {
  project = "my-project-id"
  region  = "us-central1"
}

# Create a GCP instance with Shielded VM enabled
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

  # Enable Shielded VM configuration
  shielded_instance_config {
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
