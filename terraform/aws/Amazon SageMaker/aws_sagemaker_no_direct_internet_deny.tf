provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_sagemaker_notebook_instance" "fail_test" {
  provider          = aws.fail_aws
  name              = "fail-test-notebook"
  role_arn          = "arn:aws:iam::123456789012:role/service-role/AWSGlueServiceRole-DefaultRole"
  instance_type     = "ml.t2.medium"

  # Direct internet access enabled (non-compliant)
  direct_internet_access = "Enabled"

  tags = {
    Name = "fail-test-notebook"
    Environment = "test"
  }
}