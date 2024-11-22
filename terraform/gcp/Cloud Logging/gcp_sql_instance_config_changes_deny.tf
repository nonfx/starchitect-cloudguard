provider "google" {
  alias   = "fail_aws"
  project = "my-project-id"
  region  = "us-central1"
}

# Incorrect metric filter configuration
resource "google_logging_metric" "fail_sql_changes" {
  provider = google.fail_aws
  name     = "sql-instance-config-changes-fail"
  filter   = "resource.type=\"cloudsql_database\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
  }
}

# Incorrect alert policy configuration
resource "google_monitoring_alert_policy" "fail_sql_alert" {
  provider              = google.fail_aws
  display_name          = "SQL Config Changes Alert - Fail"
  notification_channels = ["projects/my-project-id/notificationChannels/12345"]
  combiner              = "OR"

  conditions {
    display_name = "Wrong Condition Name"
    condition_threshold {
      filter          = "metric.type=\"compute.googleapis.com/instance/cpu/utilization\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.5
    }
  }
}