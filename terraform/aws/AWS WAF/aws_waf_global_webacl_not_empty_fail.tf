resource "aws_waf_web_acl" "fail_example" {
  name        = "example-waf-acl"
  metric_name = "exampleWafAcl"

  default_action {
    type = "ALLOW"
  }

  # No rules or rule groups defined
}
