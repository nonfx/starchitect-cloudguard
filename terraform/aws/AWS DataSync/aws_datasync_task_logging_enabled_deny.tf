provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_datasync_task" "fail_test" {
  provider = aws.fail_aws
  name = "fail-datasync-task"
  source_location_arn = "arn:aws:datasync:us-west-2:123456789012:location/loc-1234567890abcdef0"
  destination_location_arn = "arn:aws:datasync:us-west-2:123456789012:location/loc-0987654321fedcba0"

  # No CloudWatch logging configuration
}
