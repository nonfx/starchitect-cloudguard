provider "aws" {
  region = "us-west-2"
}

# Network Firewall policy with non-compliant configuration
resource "aws_networkfirewall_firewall_policy" "fail_policy" {
  name = "fail-policy"

  firewall_policy {
    # Non-compliant: Using pass action for stateless default
    stateless_default_actions          = ["aws:pass"]
    stateless_fragment_default_actions = ["aws:drop"]

    stateless_rule_group_reference {
      priority     = 1
      resource_arn = "arn:aws:network-firewall:us-west-2:123456789012:stateless-rulegroup/example"
    }
  }

  tags = {
    Environment = "test"
  }
}
