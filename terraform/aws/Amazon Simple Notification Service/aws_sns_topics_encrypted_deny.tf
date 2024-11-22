provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create SNS topic without KMS encryption
resource "aws_sns_topic" "fail_test" {
  provider = aws.fail_aws
  name = "fail-test-topic"

  # No KMS encryption configured

  tags = {
    Environment = "test"
    Purpose = "testing"
  }
}
