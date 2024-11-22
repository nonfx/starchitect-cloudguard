provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create WAF Regional web ACL without rules
resource "aws_wafregional_web_acl" "fail_acl" {
  provider = aws.fail_aws
  name        = "fail-web-acl"
  metric_name = "failWebAcl"

  default_action {
    type = "ALLOW"
  }

  tags = {
    Environment = "test"
  }
}