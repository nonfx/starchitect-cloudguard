provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Create custom network (compliant)
resource "google_compute_network" "pass_network" {
  provider = google.pass_google
  name                    = "custom-network"
  auto_create_subnetworks = false
  
  description = "Custom network with controlled subnet creation"
}

# Create custom subnet
resource "google_compute_subnetwork" "pass_subnet" {
  provider = google.pass_google
  name          = "custom-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = "us-central1"
  network       = google_compute_network.pass_network.id
  
  private_ip_google_access = true
  
  log_config {
    aggregation_interval = "INTERVAL_5_SEC"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}