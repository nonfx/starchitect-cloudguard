provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_sagemaker_notebook_instance" "fail_test" {
  provider      = aws.fail_aws
  name          = "fail-test-notebook"
  role_arn      = "arn:aws:iam::123456789012:role/service-role/AWSGlueServiceRole"
  instance_type = "ml.t2.medium"

  # No subnet_id specified - not in VPC

  tags = {
    Environment = "Test"
  }
}