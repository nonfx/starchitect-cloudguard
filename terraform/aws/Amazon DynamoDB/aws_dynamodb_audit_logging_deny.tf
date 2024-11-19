provider "aws" {
  region = "us-west-2"
}

# DynamoDB Table
resource "aws_dynamodb_table" "example_table" {
  name           = "example-table"
  hash_key       = "id"
  billing_mode   = "PAY_PER_REQUEST"

  attribute {
    name = "id"
    type = "S"
  }

  tags = {
    Name = "example-table"
  }
}
