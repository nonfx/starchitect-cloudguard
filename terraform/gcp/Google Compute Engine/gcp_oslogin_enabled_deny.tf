provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Project metadata without OS login enabled
resource "google_compute_project_metadata" "fail_metadata" {
  provider = google.fail_google
  metadata = {
    foo = "bar"
    # OS login not enabled
  }
}

# Instance without OS login enabled
resource "google_compute_instance" "fail_instance" {
  provider = google.fail_google
  name         = "fail-test-instance"
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
    foo = "bar"
    # OS login not enabled
  }
}