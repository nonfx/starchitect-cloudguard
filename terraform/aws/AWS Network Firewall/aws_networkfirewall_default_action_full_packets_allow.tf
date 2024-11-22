provider "aws" {
  region = "us-west-2"
}

# Network Firewall policy with compliant configuration
resource "aws_networkfirewall_firewall_policy" "pass_policy" {
  name = "pass-policy"

  firewall_policy {
    # Compliant: Using drop action for stateless default
    stateless_default_actions          = ["aws:drop"]
    stateless_fragment_default_actions = ["aws:drop"]

    stateless_rule_group_reference {
      priority     = 1
      resource_arn = "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example"
    }
  }

  tags = {
    Environment = "production"
  }
}
