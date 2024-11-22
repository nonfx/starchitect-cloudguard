provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_dynamodb_table" "failing_table" {
  provider     = aws.failing
  name         = "failing-dynamodb-table"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

# No VPC endpoint for DynamoDB is created in this failing example
