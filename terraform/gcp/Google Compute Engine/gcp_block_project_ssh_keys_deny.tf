provider "google" {
  alias = "fail_gcp"
  project = "my-project-id"
  region  = "us-central1"
}

# Create a VM instance without blocking project-wide SSH keys
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

  metadata = {
    # No block-project-ssh-keys setting, allowing project-wide SSH keys
    environment = "test"
  }

  tags = ["fail-instance"]
}