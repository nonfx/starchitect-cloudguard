provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_sns_topic" "pass_db_events" {
  provider = aws.pass_aws
  name = "pass-db-events"
}

resource "aws_db_event_subscription" "pass_test" {
  provider = aws.pass_aws
  name = "pass-test-subscription"
  sns_topic = aws_sns_topic.pass_db_events.arn
  
  # Correct source type for parameter groups
  source_type = "db-parameter-group"
  
  # Include configuration change category
  event_categories = ["configuration change"]
  
  enabled = true
  
  tags = {
    Environment = "production"
  }
}