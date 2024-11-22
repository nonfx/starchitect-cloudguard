provider "google" {
  alias   = "pass_aws"
  project = "my-project-id"
  region  = "us-central1"
}

# Correct metric filter configuration
resource "google_logging_metric" "pass_sql_changes" {
  provider = google.pass_aws
  name     = "sql-instance-config-changes-pass"
  filter   = "resource.type=\"cloudsql_database\" AND protoPayload.methodName=\"cloudsql.instances.update\""

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "user"
      value_type  = "STRING"
      description = "User who made the change"
    }
  }
}

# Correct alert policy configuration
resource "google_monitoring_alert_policy" "pass_sql_alert" {
  provider              = google.pass_aws
  display_name          = "SQL Config Changes Alert - Pass"
  notification_channels = ["projects/my-project-id/notificationChannels/12345"]
  combiner              = "OR"

  conditions {
    display_name = "SQL Instance Configuration Changes"
    condition_threshold {
      filter          = "metric.type=\"sql-instance-config-changes-pass\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
      trigger {
        count = 1
      }
    }
  }

  documentation {
    content   = "Alert for SQL instance configuration changes"
    mime_type = "text/markdown"
  }
}