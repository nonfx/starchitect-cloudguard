provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create WAF Regional rule
resource "aws_wafregional_rule" "fail_rule" {
  provider    = aws.fail_aws
  name        = "fail-rule"
  metric_name = "failRule"
}

# Create WAF Regional rule group without any rules
resource "aws_wafregional_rule_group" "fail_rule_group" {
  provider    = aws.fail_aws
  name        = "fail-rule-group"
  metric_name = "failRuleGroup"

  # No activated_rule block means no rules in the group

  tags = {
    Environment = "Development"
    Purpose     = "Testing"
  }
}