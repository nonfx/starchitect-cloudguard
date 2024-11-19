provider "aws" {
  region = "us-west-2"
}

resource "aws_dynamodb_table" "example_table" {
  name           = "example-table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 10
  write_capacity = 10
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

// missing cloudwatch config
