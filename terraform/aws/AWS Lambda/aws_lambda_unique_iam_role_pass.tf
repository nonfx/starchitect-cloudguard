provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_iam_role" "passing_lambda_role1" {
  provider = aws.passing
  name = "passing-lambda-role-1"

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

resource "aws_iam_role" "passing_lambda_role2" {
  provider = aws.passing
  name = "passing-lambda-role-2"

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

resource "aws_lambda_function" "passing_lambda1" {
  provider = aws.passing
  filename      = "lambda_function_payload.zip"
  function_name = "passing-lambda-function-1"
  role          = aws_iam_role.passing_lambda_role1.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
}

resource "aws_lambda_function" "passing_lambda2" {
  provider = aws.passing
  filename      = "lambda_function_payload.zip"
  function_name = "passing-lambda-function-2"
  role          = aws_iam_role.passing_lambda_role2.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
}
