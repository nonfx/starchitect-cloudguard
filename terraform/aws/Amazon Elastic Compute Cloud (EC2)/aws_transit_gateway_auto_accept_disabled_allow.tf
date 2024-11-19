provider "aws" {
  region = "us-west-2"
}

# Create transit gateway with auto accept disabled - this configuration follows security best practices
resource "aws_ec2_transit_gateway" "pass_test" {
  description = "pass-test-tgw"
  auto_accept_shared_attachments = "disable"  # This setting ensures manual approval of VPC attachment requests

  # Additional optional configurations for the transit gateway
  dns_support = "enable"
  vpn_ecmp_support = "enable"
  default_route_table_association = "enable"
  default_route_table_propagation = "enable"

  tags = {
    Name = "pass-test-tgw"
    Environment = "production"
  }
}
