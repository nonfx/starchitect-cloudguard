provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create DynamoDB table with deletion protection enabled
resource "aws_dynamodb_table" "pass_test_table" {
  provider = aws.pass_aws
  name = "pass-test-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key = "id"

  attribute {
    name = "id"
    type = "S"
  }

  deletion_protection_enabled = true

  tags = {
    Name = "pass-test-table"
    Environment = "test"
  }
}
