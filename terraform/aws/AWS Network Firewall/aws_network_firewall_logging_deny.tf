# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create Network Firewall without logging configuration
resource "aws_networkfirewall_firewall" "fail_firewall" {
  name     = "fail-firewall"
  vpc_id   = "vpc-12345678"

  firewall_policy_arn = "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example"
  
  subnet_mapping {
    subnet_id = "subnet-12345678"
  }

  tags = {
    Environment = "test"
  }
}