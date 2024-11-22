provider "google" {
  alias   = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Incorrect metric filter configuration
resource "google_logging_metric" "fail_vpc_changes" {
  provider = google.fail_google
  name     = "vpc-network-changes-fail"
  filter   = "resource.type=gce_network" # Missing method names
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert policy with incorrect configuration
resource "google_monitoring_alert_policy" "fail_vpc_alert" {
  provider              = google.fail_google
  display_name          = "VPC Network Changes Alert - Fail"
  notification_channels = ["projects/my-project-id/notificationChannels/12345"]
  combiner              = "OR"

  conditions {
    display_name = "VPC Changes Condition"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/vpc-network-changes-fail\""
      duration        = "0s"
      comparison      = "COMPARISON_LT" # Incorrect comparison
      threshold_value = -1              # Invalid threshold
    }
  }
}