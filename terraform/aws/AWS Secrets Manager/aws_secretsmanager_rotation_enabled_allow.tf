provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create secret with rotation enabled
resource "aws_secretsmanager_secret" "pass_test" {
  provider    = aws.pass_aws
  name        = "pass-test-secret"
  description = "Secret with rotation enabled"

  tags = {
    Environment = "production"
  }
}


resource "aws_secretsmanager_secret_rotation" "aws_secret_rotation" {
  secret_id           = aws_secretsmanager_secret.pass_test.id
  rotation_lambda_arn = aws_lambda_function.pass_test.arn

  rotation_rules {
    automatically_after_days = 30
  }
}
