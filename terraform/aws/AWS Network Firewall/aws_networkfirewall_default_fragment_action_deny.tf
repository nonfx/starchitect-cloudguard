# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a Network Firewall policy with invalid fragment action
resource "aws_networkfirewall_policy" "fail_policy" {
  name = "fail-policy"

  firewall_policy {
    # Invalid configuration using 'pass' action for fragments
    stateless_default_actions = ["aws:pass"]
    stateless_fragment_default_actions = ["aws:pass"]
  }

  tags = {
    Environment = "test"
  }
}
