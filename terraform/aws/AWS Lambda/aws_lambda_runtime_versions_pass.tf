provider "aws" {
  region = "us-west-2"
}

resource "aws_lambda_function" "passing_function" {
  filename      = "lambda_function_payload.zip"
  function_name = "passing_lambda_function"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"

  # Using a supported runtime
  runtime = "nodejs20.x"

  environment {
    variables = {
      foo = "bar"
    }
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  name = "iam_for_lambda"

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
