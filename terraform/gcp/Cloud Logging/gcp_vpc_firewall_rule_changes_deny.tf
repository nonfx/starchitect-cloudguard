provider "google" {
  alias   = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Incorrect metric filter missing required criteria
resource "google_logging_metric" "fail_metric" {
  provider = google.fail_google
  name     = "vpc-firewall-changes-fail"
  filter   = "resource.type=\"gce_firewall_rule\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Alert policy with incorrect threshold
resource "google_monitoring_alert_policy" "fail_alert" {
  provider              = google.fail_google
  display_name          = "Firewall Changes Alert - Fail"
  notification_channels = ["projects/my-project-id/notificationChannels/channel-id"]
  combiner              = "OR"

  conditions {
    display_name = "Firewall rule changes condition"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/vpc-firewall-changes-fail\""
      duration        = "300s"
      comparison      = "COMPARISON_GT"
      threshold_value = 5
    }
  }
}
