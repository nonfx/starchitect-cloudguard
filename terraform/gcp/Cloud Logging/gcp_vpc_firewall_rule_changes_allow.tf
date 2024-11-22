provider "google" {
  alias   = "pass_google"
  project = "my-project-id"
  region  = "us-central1"
}

# Correct metric filter with all required criteria
resource "google_logging_metric" "pass_metric" {
  provider = google.pass_google
  name     = "vpc-firewall-changes-pass"
  filter   = <<EOT
resource.type="gce_firewall_rule" AND
(methodName="compute.firewalls.patch" OR
methodName="compute.firewalls.insert" OR
methodName="compute.firewalls.delete")
EOT

  metric_descriptor {
    metric_kind = "DELTA"
    value_type  = "INT64"
    labels {
      key         = "resource_name"
      value_type  = "STRING"
      description = "The firewall rule name"
    }
  }
}

# Properly configured alert policy
resource "google_monitoring_alert_policy" "pass_alert" {
  provider              = google.pass_google
  display_name          = "Firewall Changes Alert - Pass"
  notification_channels = ["projects/my-project-id/notificationChannels/channel-id"]
  combiner              = "OR"

  conditions {
    display_name = "Firewall rule changes condition"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/vpc-firewall-changes-pass\""
      duration        = "0s"
      comparison      = "COMPARISON_GT"
      threshold_value = 0
    }
  }

  documentation {
    content   = "Alert for VPC firewall rule changes"
    mime_type = "text/markdown"
  }
}
