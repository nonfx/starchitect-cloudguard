provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Valid metric configuration with correct filter and metric kind
resource "google_logging_metric" "pass_metric" {
  provider = google.pass_google
  name     = "pass-role-changes"
  filter   = "resource.type=\"iam_role\" AND (protoPayload.methodName = \"google.iam.admin.v1.CreateRole\" OR protoPayload.methodName=\"google.iam.admin.v1.DeleteRole\" OR protoPayload.methodName=\"google.iam.admin.v1.UpdateRole\")"
  
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

# Alert policy with correct threshold and duration
resource "google_monitoring_alert_policy" "pass_policy" {
  provider = google.pass_google
  display_name = "Pass Role Changes Alert"
  combiner     = "OR"

  conditions {
    display_name = "Pass condition"
    condition_threshold {
      comparison = "COMPARISON_GT"
      threshold_value = 0
      duration = "0s"
      filter   = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.pass_metric.name}\""
      
      aggregations {
        alignment_period = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }
}