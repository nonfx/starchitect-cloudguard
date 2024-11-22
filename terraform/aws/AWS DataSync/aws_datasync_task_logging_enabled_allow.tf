provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_cloudwatch_log_group" "pass_test" {
  provider = aws.pass_aws
  name = "/aws/datasync/task"
  retention_in_days = 7
}

resource "aws_datasync_task" "pass_test" {
  provider = aws.pass_aws
  name = "pass-datasync-task"
  source_location_arn = "arn:aws:datasync:us-west-2:123456789012:location/loc-1234567890abcdef0"
  destination_location_arn = "arn:aws:datasync:us-west-2:123456789012:location/loc-0987654321fedcba0"
  cloudwatch_log_group_arn = aws_cloudwatch_log_group.pass_test.arn

  tags = {
    Environment = "Production"
    Service = "DataSync"
  }
}
