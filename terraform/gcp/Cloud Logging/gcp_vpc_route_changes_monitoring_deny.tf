provider "google" {
  alias   = "fail_aws"
  project = "my-project-id"
  region  = "us-central1"
}

# Invalid metric filter missing required criteria
resource "google_logging_metric" "fail_vpc_route_metric" {
  provider = google.fail_aws
  name     = "vpc-route-changes-fail"
  filter   = "resource.type=\"gce_route\""
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}