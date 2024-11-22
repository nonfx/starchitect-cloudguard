provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Project metadata with OS login enabled
resource "google_compute_project_metadata" "pass_metadata" {
  provider = google.pass_google
  metadata = {
    enable-oslogin = "true"
    environment = "production"
  }
}

# Instance with OS login enabled (although not necessary when enabled at project level)
resource "google_compute_instance" "pass_instance" {
  provider = google.pass_google
  name         = "pass-test-instance"
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

  metadata = {
    enable-oslogin = "true"
    environment = "production"
  }

  tags = {
    environment = "production"
  }
}