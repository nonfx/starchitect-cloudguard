provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_iam_role" "failing_lambda_role" {
  provider = aws.failing
  name = "failing-lambda-role"

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
}

resource "aws_lambda_function" "failing_lambda1" {
  provider = aws.failing
  filename      = "lambda_function_payload.zip"
  function_name = "failing-lambda-function-1"
  role          = aws_iam_role.failing_lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
}

resource "aws_lambda_function" "failing_lambda2" {
  provider = aws.failing
  filename      = "lambda_function_payload.zip"
  function_name = "failing-lambda-function-2"
  role          = aws_iam_role.failing_lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
}
