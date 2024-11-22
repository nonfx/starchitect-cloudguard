provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create WAF IPSet for use in rule
resource "aws_wafregional_ipset" "pass_ipset" {
  provider = aws.pass_aws
  name     = "pass-ipset"
}

# Create WAF Regional rule with condition
resource "aws_wafregional_rule" "pass_rule" {
  provider    = aws.pass_aws
  name        = "pass-rule"
  metric_name = "passRuleMetric"

  predicate {
    data_id = aws_wafregional_ipset.pass_ipset.id
    negated = false
    type    = "IPMatch"
  }

  tags = {
    Environment = "production"
  }
}
