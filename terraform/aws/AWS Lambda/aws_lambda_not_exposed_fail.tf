provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_lambda_function" "failing_exposed_function" {
  function_name = "PublicLambdaFunction"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "nodejs12.x"
  source_code_hash = filebase64sha256("lambda_function_payload.zip")
  filename         = "lambda_function_payload.zip"
}

resource "aws_lambda_permission" "failing_public_permission" {
  statement_id   = "AllowPublicInvoke"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.failing_exposed_function.function_name
  principal      = "*"
}

resource "aws_iam_role" "lambda_role" {
  name = "lambda_role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}
