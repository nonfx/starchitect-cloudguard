provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_dynamodb_table" "failing_example" {
  provider = aws.failing
  name           = "failing-dynamodb-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "Id"

  attribute {
    name = "Id"
    type = "S"
  }

  # No server-side encryption configured
  # No IAM policy attached
}
