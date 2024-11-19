provider "aws" {
  alias  = "failing"
  region = "us-west-2"
}

resource "aws_lambda_function" "failing_lambda" {
  provider      = aws.failing
  filename      = "lambda_function_payload.zip"
  function_name = "failing_lambda_function"
  role          = "arn:aws:iam::123456789012:role/non_existent_role"
  handler       = "index.test"
  runtime       = "nodejs14.x"
}
