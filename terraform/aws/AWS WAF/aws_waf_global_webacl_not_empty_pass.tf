resource "aws_waf_rule" "example_rule" {
  name        = "example-rule"
  metric_name = "exampleRule"
}

resource "aws_waf_web_acl" "pass_example" {
  name        = "example-waf-acl"
  metric_name = "exampleWafAcl"

  default_action {
    type = "ALLOW"
  }

  rules {
    action {
      type = "BLOCK"
    }

    priority = 1
    rule_id  = aws_waf_rule.example_rule.id
    type     = "REGULAR"
  }
}
