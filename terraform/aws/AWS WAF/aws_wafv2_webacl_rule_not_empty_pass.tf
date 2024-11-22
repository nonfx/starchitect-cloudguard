resource "aws_wafv2_web_acl" "example" {
  name        = "web-acl-with-rule"
  description = "Example of a Web ACL with a rule"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "rule-1"
    priority = 1

    action {
      block {}
    }

    statement {
      geo_match_statement {
        country_codes = ["US", "CA"]
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = false
      metric_name                = "rule-1-metric"
      sampled_requests_enabled   = false
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "web-acl-with-rule-metric"
    sampled_requests_enabled   = false
  }
}
