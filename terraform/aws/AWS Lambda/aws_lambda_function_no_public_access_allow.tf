provider "aws" {
  region = "us-west-2"
}

# IAM role for Lambda function
resource "aws_iam_role" "pass_lambda_role" {
  name = "pass_lambda_role"

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

# Lambda function with secure configuration
resource "aws_lambda_function" "pass_function" {
  filename         = "lambda_function_payload.zip"
  function_name    = "pass_lambda_function"
  role             = aws_iam_role.pass_lambda_role.arn
  handler          = "index.handler"
  runtime          = "nodejs14.x"

  environment {
    variables = {
      ENVIRONMENT = "production"
    }
  }
}

# Lambda permission with proper S3 access and source account condition
resource "aws_lambda_permission" "pass_permission" {
  statement_id    = "AllowS3Access"
  action          = "lambda:InvokeFunction"
  function_name   = aws_lambda_function.pass_function.function_name
  principal       = "s3.amazonaws.com"
  source_account  = "123456789012"  # Specific account ID
}
