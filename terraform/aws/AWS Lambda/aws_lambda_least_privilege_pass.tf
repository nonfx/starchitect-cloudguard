provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_iam_role" "passing_lambda_role" {
  provider = aws.passing
  name = "passing_lambda_role"
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

resource "aws_iam_role_policy" "passing_lambda_policy" {
  provider = aws.passing
  name = "passing_lambda_policy"
  role = aws_iam_role.passing_lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "arn:aws:s3:::example-bucket/*"
      }
    ]
  })
}

resource "aws_lambda_function" "passing_lambda" {
  provider = aws.passing
  filename      = "lambda_function_payload.zip"
  function_name = "passing_lambda_function"
  role          = aws_iam_role.passing_lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs14.x"
}
