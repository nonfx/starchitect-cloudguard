provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create a secret without rotation enabled
resource "aws_secretsmanager_secret" "fail_test" {
  provider = aws.fail_aws
  name = "fail-test-secret"
  description = "Secret without rotation enabled"
  
  tags = {
    Environment = "test"
  }
}