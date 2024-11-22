provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_sns_topic" "fail_db_events" {
  provider = aws.fail_aws
  name = "fail-db-events"
}

resource "aws_db_event_subscription" "fail_test" {
  provider = aws.fail_aws
  name = "fail-test-subscription"
  sns_topic = aws_sns_topic.fail_db_events.arn
  
  # Wrong source type
  source_type = "db-instance"
  
  # Missing configuration change category
  event_categories = ["deletion", "failure"]
  
  tags = {
    Environment = "test"
  }
}