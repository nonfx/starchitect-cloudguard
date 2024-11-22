provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create Inspector2 enabler without EC2 scanning
resource "aws_inspector2_enabler" "fail" {
  provider = aws.fail_aws

  account_ids = ["123456789012"]
  resource_types = ["ECR"]  # Only ECR scanning enabled, EC2 scanning missing
}
