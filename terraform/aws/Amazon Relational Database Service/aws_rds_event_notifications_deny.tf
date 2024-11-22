provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_sns_topic" "fail_test" {
  provider = aws.fail_aws
  name     = "fail-test-db-events"
}

resource "aws_db_event_subscription" "fail_test" {
  provider    = aws.fail_aws
  name        = "fail-test-subscription"
  sns_topic   = aws_sns_topic.fail_test.arn
  source_type = "db-cluster"
  enabled     = true
  
  event_categories = ["availability"] # Missing required categories
  
  tags = {
    Environment = "test"
    Purpose     = "testing"
  }
}
