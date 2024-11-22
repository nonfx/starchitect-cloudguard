provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create WAF IPSet for use in rule
resource "aws_waf_ipset" "pass_ipset" {
  provider = aws.pass_aws
  name = "pass_ipset"

  ip_set_descriptors {
    type  = "IPV4"
    value = "192.0.2.0/24"
  }
}

# Create WAF rule with predicates - this will pass the policy check
resource "aws_waf_rule" "pass_rule" {
  provider = aws.pass_aws
  name        = "pass-rule"
  metric_name = "passRule"

  predicates {
    data_id = aws_waf_ipset.pass_ipset.id
    negated = false
    type    = "IPMatch"
  }

  tags = {
    Environment = "production"
    Purpose     = "security"
  }
}