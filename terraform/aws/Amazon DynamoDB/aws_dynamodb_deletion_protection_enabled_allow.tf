provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_dynamodb_table" "pass_test_table" {
  provider = aws.pass_aws
  name           = "pass-test-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # Deletion protection is enabled
  deletion_protection_enabled = true

  point_in_time_recovery {
    enabled = true
  }

  tags = {
    Environment = "production"
    Purpose     = "data-protection"
  }
}