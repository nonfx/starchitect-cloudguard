# Configure AWS provider
provider "aws" {
  region = "us-west-2"
}

# Create a Network Firewall rule group with rules (compliant)
resource "aws_networkfirewall_rule_group" "pass_group" {
  capacity    = 100
  name        = "pass-rule-group"
  type        = "STATELESS"
  description = "Stateless rule group with rules"

  rule_group {
    rules_source {
      stateless_rules_and_custom_actions {
        stateless_rule {
          priority = 1
          rule_definition {
            actions = ["aws:pass"]
            match_attributes {
              protocols = [6]  # TCP protocol
              source {
                address_definition = "10.0.0.0/8"
              }
              destination {
                address_definition = "192.168.0.0/16"
              }
            }
          }
        }
      }
    }
  }

  tags = {
    Environment = "production"
  }
}
