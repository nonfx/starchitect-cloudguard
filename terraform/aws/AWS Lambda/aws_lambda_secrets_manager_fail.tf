provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_secretsmanager_secret" "db_credentials" {
  provider = aws.failing
  name = "db-credentials-secret"
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  provider = aws.failing
  secret_id     = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = "dbuser"
    password = "dbpassword"
  })
}

resource "aws_lambda_function" "failing_lambda_sm" {
  provider = aws.failing
  filename      = "lambda_function_payload.zip"
  function_name = "failing_lambda_function"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"

  source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "nodejs14.x"

  environment {
    variables = {
      DB_SECRET_PASS = "MY_SECRET",
      PASSWORD = "MY_PASSWORD",
      DB_SECRET_PASSWORD = "MY_PASSWORD",
    }
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  provider = aws.failing
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

resource "aws_iam_role_policy_attachment" "lambda_secrets_manager" {
  provider = aws.failing
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
  role       = aws_iam_role.iam_for_lambda.name
}
