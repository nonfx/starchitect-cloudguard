provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_sagemaker_notebook_instance" "pass_test" {
  provider          = aws.pass_aws
  name              = "pass-test-notebook"
  role_arn          = "arn:aws:iam::123456789012:role/service-role/AWSGlueServiceRole-DefaultRole"
  instance_type     = "ml.t2.medium"

  # Direct internet access disabled (compliant)
  direct_internet_access = "Disabled"

  tags = {
    Name = "pass-test-notebook"
    Environment = "production"
  }
}