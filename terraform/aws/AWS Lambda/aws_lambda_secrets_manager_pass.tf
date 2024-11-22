provider "aws" {
  alias  = "passing"
  region = "us-west-2"
}

resource "aws_secretsmanager_secret" "db_credentials" {
  provider = aws.passing
  name = "db-credentials-secret"
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  provider = aws.passing
  secret_id     = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = "dbuser"
    password = "dbpassword"
  })
}

resource "aws_lambda_function" "passing_lambda_sm" {
  provider = aws.passing
  filename      = "lambda_function_payload.zip"
  function_name = "passing_lambda_function"
  role          = aws_iam_role.iam_for_lambda.arn
  handler       = "index.handler"

  source_code_hash = filebase64sha256("lambda_function_payload.zip")

  runtime = "nodejs14.x"

  environment {
    variables = {
      DB_SECRET_PASS = "${aws_secretsmanager_secret.db_credentials.arn}",
      PASSWORD = "${aws_secretsmanager_secret.db_credentials.arn}",
      DB_SECRET_PASSWORD = "${aws_secretsmanager_secret.db_credentials.arn}",
    }
  }
}

resource "aws_iam_role" "iam_for_lambda" {
  provider = aws.passing
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
  provider = aws.passing
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
  role       = aws_iam_role.iam_for_lambda.name
}
