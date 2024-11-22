provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create disabled GuardDuty detector
resource "aws_guardduty_detector" "fail" {
  provider = aws.fail_aws
  enable = false

  tags = {
    Environment = "test"
  }
}
