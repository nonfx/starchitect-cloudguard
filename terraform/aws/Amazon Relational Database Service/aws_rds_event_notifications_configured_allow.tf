provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_sns_topic" "pass_db_events" {
  provider = aws.pass_aws
  name = "pass-rds-events"
}

resource "aws_db_event_subscription" "pass_test" {
  provider = aws.pass_aws
  name = "pass-test-subscription"
  sns_topic = aws_sns_topic.pass_db_events.arn
  
  source_type = "db-instance"
  enabled = true
  
  # Include all required event categories
  event_categories = [
    "maintenance",
    "configuration change",
    "failure"
  ]

  tags = {
    Environment = "production"
  }
}
