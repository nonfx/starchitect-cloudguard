provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create SQS queue without encryption
resource "aws_sqs_queue" "fail_test" {
  provider = aws.fail_aws
  name = "fail-test-queue"

  # No encryption configuration
  sqs_managed_sse_enabled = false
  
  tags = {
    Environment = "test"
    Purpose = "testing"
  }
}
