provider "aws" {
  alias = "fail_aws"
  region = "us-west-2"
}

# Create transit gateway with auto accept enabled - this configuration fails security best practices
resource "aws_ec2_transit_gateway" "fail_test" {
  provider = aws.fail_aws
  description = "fail-test-tgw"
  auto_accept_shared_attachments = "enable"  # This setting automatically accepts VPC attachment requests, which is not recommended

  tags = {
    Name = "fail-test-tgw"
    Environment = "test"
  }
}
