provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

resource "aws_networkfirewall_firewall" "fail_firewall" {
  provider = aws.fail_aws
  name     = "fail-test-firewall"
  vpc_id   = "vpc-12345678"

  subnet_mapping {
    subnet_id = "subnet-12345678"
  }

  firewall_policy_arn = "arn:aws:network-firewall:us-west-2:123456789012:firewall-policy/example"
  delete_protection   = false

  tags = {
    Environment = "test"
  }
}