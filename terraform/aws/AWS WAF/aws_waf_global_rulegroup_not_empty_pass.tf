resource "aws_waf_rule" "example" {
  name        = "example-rule"
  metric_name = "exampleRule"
}

resource "aws_waf_rule_group" "pass_example" {
  name        = "example-waf-rule-group"
  metric_name = "ExampleWafRuleGroup"

  activated_rule {
    action {
      type = "COUNT"
    }
    priority = 50
    rule_id  = aws_waf_rule.example.id
  }
}
