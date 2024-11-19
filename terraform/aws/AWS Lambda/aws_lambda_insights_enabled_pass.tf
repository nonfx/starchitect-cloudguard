provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_lambda_function" "passing_lambda" {
  provider      = aws.passing
  filename      = "lambda_function_payload.zip"
  function_name = "passing_lambda_function"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.test"
  runtime       = "nodejs14.x"

  layers = ["arn:aws:lambda:us-west-2:580247275435:layer:LambdaInsightsExtension:14"]

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
      },
    ]
  })
}
