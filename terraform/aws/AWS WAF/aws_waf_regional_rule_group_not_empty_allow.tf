provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create WAF Regional rule
resource "aws_wafregional_rule" "pass_rule" {
  provider    = aws.pass_aws
  name        = "pass-rule"
  metric_name = "passRule"
}

# Create WAF Regional rule group with at least one rule
resource "aws_wafregional_rule_group" "pass_rule_group" {
  provider    = aws.pass_aws
  name        = "pass-rule-group"
  metric_name = "passRuleGroup"

  activated_rule {
    action {
      type = "BLOCK"
    }
    priority = 1
    rule_id  = aws_wafregional_rule.pass_rule.id
    type     = "REGULAR"
  }

  tags = {
    Environment = "Production"
    Security    = "High"
  }
}