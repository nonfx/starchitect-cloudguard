# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create an SNS topic for notifications (passing case)
resource "aws_sns_topic" "pass_db_events" {
  name = "pass-rds-events"
}

# Create an event subscription with security group monitoring (passing case)
resource "aws_db_event_subscription" "pass_test" {
  name = "pass-test-subscription"
  sns_topic = aws_sns_topic.pass_db_events.arn
  # Correct source_type for monitoring security group events
  source_type = "db-security-group"
  
  event_categories = [
    "configuration change",
    "failure"
  ]

  tags = {
    Environment = "production"
  }
}
