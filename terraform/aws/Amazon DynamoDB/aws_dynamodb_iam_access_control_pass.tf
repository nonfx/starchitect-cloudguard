provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_dynamodb_table" "passing_example" {
  provider = aws.passing
  name           = "passing-dynamodb-table"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "Id"

  attribute {
    name = "Id"
    type = "S"
  }

  server_side_encryption {
    enabled = true
  }
}

resource "aws_dynamodb_resource_policy" "passing_example" {
  provider = aws.passing
  resource_arn = aws_dynamodb_table.passing_example.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowAccessFromIAMRole"
        Effect    = "Allow"
        Principal = {
          AWS = "arn:aws:iam::123456789012:role/example-role"
        }
        Action = [
          "dynamodb:BatchGetItem",
          "dynamodb:BatchWriteItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:GetItem",
          "dynamodb:Scan",
          "dynamodb:Query",
          "dynamodb:UpdateItem"
        ]
        Resource = "arn:aws:dynamodb:us-west-2:123456789012:table/${aws_dynamodb_table.passing_example.name}"
      }
    ]
  })
}
