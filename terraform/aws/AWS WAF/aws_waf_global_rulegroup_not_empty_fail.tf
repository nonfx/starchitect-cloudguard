resource "aws_waf_rule_group" "fail_example" {
  name        = "example-waf-rule-group"
  metric_name = "ExampleWafRuleGroup"

  # No activated_rule block, which means no rules in the group
}
