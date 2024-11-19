provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_lambda_function" "pass_function_runtime" {
  provider = aws.pass_aws
  filename = "lambda_function_payload.zip"
  function_name = "pass_lambda_function_runtime"
  role = "arn:aws:iam::123456789012:role/lambda-role"
  handler = "index.handler"
  runtime = "nodejs20.x"  # Supported runtime

  environment {
    variables = {
      foo = "bar"
    }
  }
}

resource "aws_lambda_function" "pass_function_image" {
  provider = aws.pass_aws
  function_name = "pass_lambda_function_image"
  role = "arn:aws:iam::123456789012:role/lambda-role"
  package_type = "Image"  # Image-based Lambda functions are allowed
  image_uri = "123456789012.dkr.ecr.us-west-2.amazonaws.com/lambda-image:latest"
}
