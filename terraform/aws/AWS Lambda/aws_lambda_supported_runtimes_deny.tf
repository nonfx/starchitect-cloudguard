provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_lambda_function" "fail_function" {
  provider = aws.fail_aws
  filename = "lambda_function_payload.zip"
  function_name = "fail_lambda_function"
  role = "arn:aws:iam::123456789012:role/lambda-role"
  handler = "index.handler"
  runtime = "nodejs14.x"  # Unsupported runtime

  environment {
    variables = {
      foo = "bar"
    }
  }
}
