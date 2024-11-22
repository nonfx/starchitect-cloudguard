provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create Route53 zone without query logging
resource "aws_route53_zone" "fail_zone" {
  provider = aws.fail_aws
  name = "example-fail.com"

  tags = {
    Environment = "test"
  }
}
