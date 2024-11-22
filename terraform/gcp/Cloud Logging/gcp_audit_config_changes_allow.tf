provider "google" {
  alias = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

resource "google_logging_metric" "pass_metric" {
  provider = google.pass_google
  name     = "pass-audit-config-changes"
  filter   = "protoPayload.methodName=\"SetIamPolicy\" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*"
  
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    unit        = "1"
  }
}

resource "google_monitoring_alert_policy" "pass_policy" {
  provider = google.pass_google
  display_name = "Pass Audit Config Changes Alert"
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