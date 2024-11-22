provider "google" {
  alias = "pass_google"
  project = "my-project"
  region  = "us-central1"
}

# Create a custom service account
resource "google_service_account" "pass_sa" {
  provider = google.pass_google
  account_id   = "custom-sa"
  display_name = "Custom Service Account"
}

# Create a VM instance with custom service account and limited access
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

  service_account {
    email  = google_service_account.pass_sa.email
    scopes = [
      "https://www.googleapis.com/auth/compute.readonly",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring.write"
    ]
  }

  tags = {
    environment = "production"
  }
}