provider "aws" {
  alias = "pass_aws"
  region = "us-west-2"
}

# Create Inspector2 enabler with EC2 scanning enabled
resource "aws_inspector2_enabler" "pass" {
  provider = aws.pass_aws

  account_ids = ["123456789012"]
  resource_types = ["EC2", "ECR", "LAMBDA"]  # EC2 scanning enabled along with other services
}
