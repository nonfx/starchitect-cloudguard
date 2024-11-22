provider "google" {
  alias   = "pass_aws"
  project = "my-project-id"
  region  = "us-central1"
}

# Properly configured metric filter
resource "google_logging_metric" "pass_vpc_route_metric" {
  provider = google.pass_aws
  name     = "vpc-route-changes-pass"
  filter   = "resource.type=\"gce_route\" AND (methodName=\"compute.routes.delete\" OR methodName=\"compute.routes.insert\")"
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "route_change_type"
      value_type  = "STRING"
      description = "Type of route change (insert or delete)"
    }
  }
}