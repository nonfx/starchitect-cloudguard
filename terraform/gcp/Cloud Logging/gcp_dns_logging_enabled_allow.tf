provider "google" {
  project = "my-project-id"
  region  = "us-central1"
  alias   = "pass_aws"
}

# Create VPC network
resource "google_compute_network" "pass_network" {
  provider = google.pass_aws
  name                    = "pass-network"
  auto_create_subnetworks = false
}

# Create DNS policy with logging enabled
resource "google_dns_policy" "pass_policy" {
  provider = google.pass_aws
  name = "pass-dns-policy"
  enable_logging = true
  
  networks {
    network_url = google_compute_network.pass_network.id
  }
}