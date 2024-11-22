provider "google" {
  alias = "fail_gcp"
  project = "my-project-id"
  region  = "us-central1"
}

# Create compute instance with default service account
resource "google_compute_instance" "fail_instance" {
  provider = google.fail_gcp
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

  # Using default compute service account
  service_account {
    email  = "123456789-compute@developer.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
}