provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

resource "aws_vpc" "fail_vpc" {
  provider = aws.fail_aws
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "fail_subnet" {
  provider = aws.fail_aws
  vpc_id = aws_vpc.fail_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
}

resource "aws_lambda_function" "fail_function" {
  provider = aws.fail_aws
  filename = "lambda_function_payload.zip"
  function_name = "fail_lambda"
  role = "arn:aws:iam::123456789012:role/lambda-role"
  handler = "index.handler"
  runtime = "nodejs18.x"

  vpc_config {
    subnet_ids = [aws_subnet.fail_subnet.id]
    security_group_ids = []
  }
}
