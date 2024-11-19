provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create WAF Regional rule without any conditions
resource "aws_wafregional_rule" "fail_rule" {
  provider = aws.fail_aws
  name        = "fail-rule"
  metric_name = "failRuleMetric"

  tags = {
    Environment = "test"
  }
}