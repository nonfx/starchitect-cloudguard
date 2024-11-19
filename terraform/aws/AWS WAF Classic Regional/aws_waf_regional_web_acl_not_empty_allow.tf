provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create WAF Regional rule
resource "aws_wafregional_rule" "pass_rule" {
  provider = aws.pass_aws
  name        = "pass-rule"
  metric_name = "passRule"

  predicate {
    data_id = aws_wafregional_ipset.pass_ipset.id
    negated = false
    type    = "IPMatch"
  }
}

# Create IP set for rule
resource "aws_wafregional_ipset" "pass_ipset" {
  provider = aws.pass_aws
  name = "pass-ipset"
}

# Create WAF Regional web ACL with rule
resource "aws_wafregional_web_acl" "pass_acl" {
  provider = aws.pass_aws
  name        = "pass-web-acl"
  metric_name = "passWebAcl"

  default_action {
    type = "ALLOW"
  }

  rule {
    priority = 1
    rule_id  = aws_wafregional_rule.pass_rule.id
    type     = "REGULAR"

    action {
      type = "BLOCK"
    }
  }

  tags = {
    Environment = "production"
  }
}