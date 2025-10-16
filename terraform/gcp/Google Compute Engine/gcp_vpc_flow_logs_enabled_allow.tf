provider "google" {
  project = "my-project"
  region  = "us-central1"
}

resource "google_compute_network" "pass_vpc" {
  name                    = "pass-vpc"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "pass_subnet" {
  name          = "pass-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = "us-central1"
  network       = google_compute_network.pass_vpc.id

  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 1
    metadata             = "INCLUDE_ALL_METADATA"
  }
}
