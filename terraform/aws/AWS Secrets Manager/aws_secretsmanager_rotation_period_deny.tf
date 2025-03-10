provider "aws" {
  region = "us-west-2"
}

resource "aws_secretsmanager_secret" "non_compliant_secret" {
  name = "non_compliant_secret"
}

resource "aws_lambda_function" "example_rotation_lambda" {
  function_name = "rotate_secret_lambda"
  runtime       = "python3.8"
  handler       = "index.handler"
  # Additional configuration here
  role = "arn:aws:iam::123456789012:role/lambda-role"
}

# Non-compliant rotation rule: rotation interval set to 60 days
resource "aws_secretsmanager_secret_rotation" "example_rotation" {
  secret_id           = aws_secretsmanager_secret.non_compliant_secret.id
  rotation_lambda_arn = aws_lambda_function.example_rotation_lambda.arn

  rotation_rules {
    automatically_after_days = 60
  }
}
