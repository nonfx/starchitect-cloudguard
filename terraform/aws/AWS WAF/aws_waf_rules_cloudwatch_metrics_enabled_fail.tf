resource "aws_wafv2_rule_group" "fail_example" {
  name     = "example-rule-group"
  scope    = "REGIONAL"
  capacity = 10

  rule {
    name     = "rule-1"
    priority = 1

    action {
      allow {}
    }

    statement {
      geo_match_statement {
        country_codes = ["US", "CA"]
      }
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "example-rule-group-metric"
    sampled_requests_enabled   = false
  }
}
