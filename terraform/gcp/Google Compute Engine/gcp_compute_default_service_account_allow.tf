provider "google" {
  alias = "pass_gcp"
  project = "my-project-id"
  region  = "us-central1"
}

# Create custom service account
resource "google_service_account" "custom_sa" {
  provider = google.pass_gcp
  account_id   = "custom-sa"
  display_name = "Custom Service Account"
}

# Create compute instance with custom service account
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

  # Using custom service account with minimal permissions
  service_account {
    email  = google_service_account.custom_sa.email
    scopes = ["compute.readonly"]
  }
}