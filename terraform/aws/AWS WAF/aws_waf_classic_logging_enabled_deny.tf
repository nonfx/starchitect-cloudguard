# Configure AWS provider for us-east-1 region (required for WAF Classic Global)
provider "aws" {
  region = "us-east-1"
}

# Create a WAF Web ACL without logging configuration
resource "aws_waf_web_acl" "fail_waf_acl" {
  name        = "fail-waf-acl"
  metric_name = "failWafAcl"

  # Define default action for the Web ACL
  default_action {
    type = "ALLOW"
  }

  # Add a sample rule
  rules {
    action {
      type = "BLOCK"
    }
    priority = 1
    rule_id  = aws_waf_rule.fail_waf_rule.id
    type     = "REGULAR"
  }
}

# Create a basic WAF rule
resource "aws_waf_rule" "fail_waf_rule" {
  name        = "fail-waf-rule"
  metric_name = "failWafRule"
}