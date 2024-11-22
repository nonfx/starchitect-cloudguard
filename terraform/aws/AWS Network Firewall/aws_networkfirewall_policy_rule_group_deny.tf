# Configure AWS Provider
provider "aws" {
  alias  = "fail_aws"
  region = "us-west-2"
}

# Create Network Firewall Policy without any rule groups
resource "aws_networkfirewall_policy" "fail_policy" {
  provider = aws.fail_aws
  name     = "fail-policy"

  firewall_policy {
    # Define default actions for stateless rules
    stateless_default_actions = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
  }

  tags = {
    Environment = "test"
  }
}
