provider "google" {
  project = "my-project-id"
  region  = "us-central1"
  alias   = "pass_aws"
}

# Correctly configured log metric filter
resource "google_logging_metric" "pass_ownership_changes" {
  provider = google.pass_aws
  name     = "pass-project-ownership-changes"
  filter   = "resource.type=\"project\" AND protoPayload.serviceName=\"cloudresourcemanager.googleapis.com\" AND protoPayload.methodName=(\"SetIamPolicy\" OR \"setIamPolicy\") AND protoPayload.serviceData.policyDelta.bindingDeltas.action=(\"ADD\" OR \"REMOVE\") AND protoPayload.serviceData.policyDelta.bindingDeltas.role=\"roles/owner\""

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "Project Ownership Changes"
  }
}

# Correctly configured alert policy
resource "google_monitoring_alert_policy" "pass_ownership_alert" {
  provider     = google.pass_aws
  display_name = "pass-Project Ownership Changes Alert"
  combiner     = "OR"

  conditions {
    display_name = "pass-Project ownership changes detected"
    condition_threshold {
      filter          = "resource.type = \"metric\" AND metric.type = \"logging.googleapis.com/user/project_ownership_changes\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }

  notification_channels = ["projects/my-project-id/notificationChannels/channel-id"]

  documentation {
    content   = "Alert triggered when project ownership changes are detected"
    mime_type = "text/markdown"
  }

  alert_strategy {
    notification_rate_limit {
      period = "300s"
    }
  }
}
