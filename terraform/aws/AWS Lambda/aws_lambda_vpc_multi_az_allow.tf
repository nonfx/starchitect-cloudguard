provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "pass_subnet_1" {
  provider = aws.pass_aws
  vpc_id = aws_vpc.pass_vpc.id
  cidr_block = "10.0.1.0/24"
  availability_zone = "us-west-2a"
}

resource "aws_subnet" "pass_subnet_2" {
  provider = aws.pass_aws
  vpc_id = aws_vpc.pass_vpc.id
  cidr_block = "10.0.2.0/24"
  availability_zone = "us-west-2b"
}

resource "aws_lambda_function" "pass_function" {
  provider = aws.pass_aws
  filename = "lambda_function_payload.zip"
  function_name = "pass_lambda"
  role = "arn:aws:iam::123456789012:role/lambda-role"
  handler = "index.handler"
  runtime = "nodejs18.x"

  vpc_config {
    subnet_ids = [aws_subnet.pass_subnet_1.id, aws_subnet.pass_subnet_2.id]
    security_group_ids = []
  }
}
