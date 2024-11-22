resource "aws_wafv2_web_acl" "example" {
  name        = "empty-web-acl"
  description = "Example of an empty Web ACL"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  visibility_config {
    cloudwatch_metrics_enabled = false
    metric_name                = "empty-web-acl-metric"
    sampled_requests_enabled   = false
  }
}
