provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create WAF rule without any predicates - this will fail the policy check
resource "aws_waf_rule" "fail_rule" {
  provider = aws.fail_aws
  name        = "fail-rule"
  metric_name = "failRule"

  tags = {
    Environment = "test"
    Purpose     = "testing"
  }
}