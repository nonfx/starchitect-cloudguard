# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a Network Firewall policy with valid fragment action
resource "aws_networkfirewall_policy" "pass_policy" {
  name = "pass-policy"

  firewall_policy {
    # Valid configuration using 'drop' action for fragments
    stateless_default_actions = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:drop"]

    # Include rule group reference
    stateless_rule_group_reference {
      priority = 1
      resource_arn = "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example"
    }
  }

  tags = {
    Environment = "production"
    Purpose = "Security"
  }
}
