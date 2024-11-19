provider "aws" {
  region = "us-west-2"
}

resource "aws_dynamodb_table" "failing_table" {
  name           = "failing-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  # Encryption at rest is not enabled
}
