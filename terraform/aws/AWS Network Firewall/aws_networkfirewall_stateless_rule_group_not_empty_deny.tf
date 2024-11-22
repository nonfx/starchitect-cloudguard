# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a Network Firewall rule group without any rules (non-compliant)
resource "aws_networkfirewall_rule_group" "fail_group" {
  capacity    = 100
  name        = "fail-rule-group"
  type        = "STATELESS"
  description = "Empty stateless rule group"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {}
    }
  }

  tags = {
    Environment = "test"
  }
}
