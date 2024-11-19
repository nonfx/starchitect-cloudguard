provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_dynamodb_table" "fail_test_table" {
  provider = aws.fail_aws
  name           = "fail-test-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # Deletion protection is not enabled
  deletion_protection_enabled = false

  tags = {
    Environment = "test"
    Purpose     = "testing"
  }
}