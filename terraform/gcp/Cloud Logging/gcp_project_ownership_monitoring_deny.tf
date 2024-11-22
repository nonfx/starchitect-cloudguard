provider "google" {
  project = "my-project-id"
  region  = "us-central1"
  alias   = "fail_aws"
}

# Incorrectly configured log metric filter
resource "google_logging_metric" "fail_ownership_changes" {
  provider = google.fail_aws
  name     = "fail-project-ownership-changes"
  filter   = "resource.type=\"project\" AND protoPayload.methodName=\"SetIamPolicy\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Incorrectly configured alert policy
resource "google_monitoring_alert_policy" "fail_ownership_alert" {
  provider     = google.fail_aws
  display_name = "fail-Project Ownership Changes Alert"
  combiner     = "OR"

  conditions {
    display_name = "fail-test condition"
    condition_threshold {
      filter          = "metric.type = \"compute.googleapis.com/instance/cpu/utilization\""
      duration        = "60s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0.5
    }
  }
}
