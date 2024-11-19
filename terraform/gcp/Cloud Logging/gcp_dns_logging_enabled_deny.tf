provider "google" {
  project = "my-project-id"
  region  = "us-central1"
  alias   = "fail_aws"
}

# Create VPC network without DNS logging
resource "google_compute_network" "fail_network" {
  provider = google.fail_aws
  name                    = "fail-network"
  auto_create_subnetworks = false
}

# Create DNS policy without logging enabled
resource "google_dns_policy" "fail_policy" {
  provider = google.fail_aws
  name = "fail-dns-policy"
  enable_logging = false
  
  networks {
    network_url = google_compute_network.fail_network.id
  }
}