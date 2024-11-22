provider "google" {
  alias = "fail_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Invalid metric configuration with incorrect filter and metric kind
resource "google_logging_metric" "fail_metric" {
  provider = google.fail_google
  name     = "fail-role-changes"
  filter   = "resource.type=\"iam_role\""
  
  metric_descriptor {
    metric_kind = "GAUGE"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy with incorrect threshold and duration
resource "google_monitoring_alert_policy" "fail_policy" {
  provider = google.fail_google
  display_name = "Fail Role Changes Alert"
  combiner     = "OR"

  conditions {
    display_name = "Fail condition"
    condition_threshold {
      comparison = "COMPARISON_GT"
      threshold_value = 1
      duration = "300s"
      filter   = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.fail_metric.name}\""
    }
  }
}