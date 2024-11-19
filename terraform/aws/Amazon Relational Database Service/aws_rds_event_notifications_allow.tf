provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_sns_topic" "pass_test" {
  provider = aws.pass_aws
  name     = "pass-test-db-events"
}

resource "aws_db_event_subscription" "pass_test" {
  provider    = aws.pass_aws
  name        = "pass-test-subscription"
  sns_topic   = aws_sns_topic.pass_test.arn
  source_type = "db-cluster"
  enabled     = true

  event_categories = ["maintenance", "failure"] # Includes all required categories

  tags = {
    Environment = "production"
    Purpose     = "monitoring"
  }
}
