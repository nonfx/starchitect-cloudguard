# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create an SNS topic for notifications (failing case)
resource "aws_sns_topic" "fail_db_events" {
  name = "fail-rds-events"
}

# Create an event subscription without security group monitoring (failing case)
resource "aws_db_event_subscription" "fail_test" {
  name = "fail-test-subscription"
  sns_topic = aws_sns_topic.fail_db_events.arn
  # Incorrect source_type that doesn't monitor security group events
  source_type = "db-instance"
  
  event_categories = [
    "availability",
    "backup",
    "maintenance"
  ]

  tags = {
    Environment = "test"
  }
}
