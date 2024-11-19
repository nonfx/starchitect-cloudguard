provider "aws" {
  region = "us-west-2"
}

# IAM role for Lambda function
resource "aws_iam_role" "fail_lambda_role" {
  name = "fail_lambda_role"

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

# Lambda function with basic configuration
resource "aws_lambda_function" "fail_function" {
  filename         = "lambda_function_payload.zip"
  function_name    = "fail_lambda_function"
  role             = aws_iam_role.fail_lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs14.x"

  environment {
    variables = {
      ENVIRONMENT = "production"
    }
  }
}

# Lambda permission that allows public access (this will fail the test)
resource "aws_lambda_permission" "fail_permission" {
  statement_id  = "AllowPublicAccess"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.fail_function.function_name
  principal     = "*"  # Public access is not recommended
}
