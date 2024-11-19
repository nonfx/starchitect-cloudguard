provider "aws" {
  region = "us-west-2"
}

resource "aws_dynamodb_table" "example_failing" {
  name           = "example-table"
  billing_mode   = "PROVISIONED"
  read_capacity  = 1
  write_capacity = 1
  hash_key       = "id"

  attribute {
    name = "id"
    type = "S"
  }
}

resource "aws_dynamodb_table_policy" "example_failing" {
    table   = aws_dynamodb_table.example.name
    policy = jsonencode({
      Version = "2012-10-17",
      Statement = [
        {
          Effect = "Allow",
          Principal = {
            AWS = "arn:aws:iam::123456789012:user/SpecificUser"
          },
          Action = "dynamodb:GetItem",
          Resource = aws_dynamodb_table.example.arn
        }
      ]
    })
  }

resource "aws_iam_policy" "dynamodb_failing_policy" {
  name        = "DynamoDBAccessPolicy"
  description = "Allow access to DynamoDB tables"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateItem"
        ],
        Resource = "arn:aws:dynamodb:us-east-1:123456789012:table/*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "app_role_failing_policy" {
  name = "AppRolePolicy"
  role = aws_iam_role.app_role.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "dynamodb:GetItem",
        Resource = "arn:aws:dynamodb:us-east-1:123456789012:table/*"
      }
    ]
  })
}

resource "aws_iam_user_policy" "user_failing_policy" {
  name = "UserPolicy"
  user = aws_iam_user.user.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "dynamodb:GetItem",
        Resource = "arn:aws:dynamodb:us-east-1:123456789012:table/*"
      }
    ]
  })
}

resource "aws_iam_group_policy" "group_failing_policy" {
  name = "GroupPolicy"
  group = aws_iam_group.group.id
  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = "dynamodb:GetItem",
        Resource = "arn:aws:dynamodb:us-east-1:123456789012:table/*"
      }
    ]
  })
}
