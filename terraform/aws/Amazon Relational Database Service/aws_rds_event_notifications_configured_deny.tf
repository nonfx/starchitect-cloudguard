provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_sns_topic" "fail_db_events" {
  provider = aws.fail_aws
  name = "fail-rds-events"
}

resource "aws_db_event_subscription" "fail_test" {
  provider = aws.fail_aws
  name = "fail-test-subscription"
  sns_topic = aws_sns_topic.fail_db_events.arn
  
  source_type = "db-instance"
  enabled = true
  
  # Missing required event categories
  event_categories = [
    "maintenance",
    "failure"
    # missing "configuration change"
  ]

  tags = {
    Environment = "test"
  }
}
