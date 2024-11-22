provider "aws" {
  region = "us-west-2"
}

resource "aws_dynamodb_table" "passing_table" {
  name           = "passing-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}
