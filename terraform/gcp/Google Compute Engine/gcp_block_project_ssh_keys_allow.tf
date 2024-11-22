provider "google" {
  alias = "pass_gcp"
  project = "my-project-id"
  region  = "us-central1"
}

# Create a VM instance with project-wide SSH keys blocked
resource "google_compute_instance" "pass_instance" {
  provider = google.pass_gcp
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
    # Block project-wide SSH keys
    block-project-ssh-keys = "true"
    environment = "production"
  }

  service_account {
    scopes = ["cloud-platform"]
  }

  tags = ["pass-instance"]
}