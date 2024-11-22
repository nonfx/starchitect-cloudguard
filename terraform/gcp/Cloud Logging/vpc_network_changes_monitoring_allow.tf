provider "google" {
  alias   = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Correct metric filter configuration
resource "google_logging_metric" "pass_vpc_changes" {
  provider = google.pass_google
  name     = "vpc-network-changes-pass"
  filter   = "resource.type=gce_network AND (protoPayload.methodName:insert OR protoPayload.methodName:patch OR protoPayload.methodName:delete OR protoPayload.methodName:removePeering OR protoPayload.methodName:addPeering)"
  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "resource_type"
      value_type  = "STRING"
      description = "Type of GCP resource"
    }
  }
}

# Properly configured alert policy
resource "google_monitoring_alert_policy" "pass_vpc_alert" {
  provider              = google.pass_google
  display_name          = "VPC Network Changes Alert - Pass"
  notification_channels = ["projects/my-project-id/notificationChannels/12345"]
  combiner              = "OR"

  conditions {
    display_name = "VPC Changes Condition"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/vpc-network-changes-pass\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0

      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_COUNT"
      }
    }
  }

  documentation {
    content   = "Alert for VPC network changes"
    mime_type = "text/markdown"
  }
}