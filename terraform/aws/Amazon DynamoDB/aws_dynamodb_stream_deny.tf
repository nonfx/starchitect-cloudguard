provider "aws" {
  region = "us-west-2"
}

resource "aws_dynamodb_table" "failing_table" {
  name           = "failing-table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
  stream_enabled                 = false
}
