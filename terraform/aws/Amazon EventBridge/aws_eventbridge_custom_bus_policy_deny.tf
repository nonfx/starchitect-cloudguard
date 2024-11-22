provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create custom event bus without policy (non-compliant)
resource "aws_cloudwatch_event_bus" "fail_bus" {
  provider = aws.fail_aws
  name     = "fail-test-bus"

  tags = {
    Environment = "test"
  }
}