provider "google" {
  project = "my-project"
  region  = "us-central1"
}

resource "google_compute_network" "fail_vpc" {
  name                    = "fail-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "fail_subnet" {
  name          = "fail-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = "us-central1"
  network       = google_compute_network.fail_vpc.id

  # No log_config block - Flow logs not enabled
}
