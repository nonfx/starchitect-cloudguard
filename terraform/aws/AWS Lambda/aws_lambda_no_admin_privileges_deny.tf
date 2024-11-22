provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_iam_role" "failing_lambda_role" {
  provider = aws.failing
  name     = "failing_lambda_execution_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
  inline_policy {
    name = "failing_inline_policy"
    policy = jsonencode({
        Version = "2012-10-17"
        Statement = [
        {
            Effect = "Allow"
            Action = ["*"]
            Resource = ["*"]
        }
        ]
    })
  }
}

resource "aws_iam_role_policy" "failing_lambda_policy" {
  provider = aws.failing
  name = "failing_lambda_policy"
  role = aws_iam_role.failing_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["*"]
        Resource = ["*"]
      }
    ]
  })
}

resource "aws_lambda_function" "failing_lambda" {
  provider      = aws.failing
  filename      = "lambda_function_payload.zip"
  function_name = "failing_lambda_function"
  role          = aws_iam_role.failing_lambda_role.arn
  handler       = "index.test"
  runtime       = "nodejs14.x"
}
