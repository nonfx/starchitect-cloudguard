provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_vpc" "pass_vpc" {
  provider = aws.pass_aws
  cidr_block = "10.0.0.0/16"

  tags = {
    Name = "pass-vpc"
  }
}

resource "aws_subnet" "pass_subnet" {
  provider = aws.pass_aws
  vpc_id     = aws_vpc.pass_vpc.id
  cidr_block = "10.0.1.0/24"

  tags = {
    Name = "pass-subnet"
  }
}

resource "aws_sagemaker_notebook_instance" "pass_test" {
  provider      = aws.pass_aws
  name          = "pass-test-notebook"
  role_arn      = "arn:aws:iam::123456789012:role/service-role/AWSGlueServiceRole"
  instance_type = "ml.t2.medium"
  subnet_id     = aws_subnet.pass_subnet.id

  tags = {
    Environment = "Test"
  }
}