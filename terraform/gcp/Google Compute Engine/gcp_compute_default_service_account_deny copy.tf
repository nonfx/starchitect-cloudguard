provider "google" {
  alias = "fail_google"
  project = "my-project"
  region  = "us-central1"
}

# Create a VM instance with default service account and full access
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

  service_account {
    email  = "default"
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  tags = {
    environment = "test"
  }
}