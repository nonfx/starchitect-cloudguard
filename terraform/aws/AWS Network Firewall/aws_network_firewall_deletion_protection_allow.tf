provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

resource "aws_networkfirewall_firewall" "pass_firewall" {
  provider = aws.pass_aws
  name     = "pass-test-firewall"
  vpc_id   = "vpc-12345678"

  subnet_mapping {
    subnet_id = "subnet-12345678"
  }

  firewall_policy_arn = "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example"
  delete_protection   = true

  tags = {
    Environment = "production"
  }
}