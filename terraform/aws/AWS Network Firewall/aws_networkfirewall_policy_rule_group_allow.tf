# Configure AWS Provider
provider "aws" {
  alias  = "pass_aws"
  region = "us-west-2"
}

# Create Network Firewall Rule Group
resource "aws_networkfirewall_rule_group" "pass_rule_group" {
  provider    = aws.pass_aws
  capacity    = 100
  name        = "pass-rule-group"
  type        = "STATEFUL"
  
  rule_group {
    rules_source {
      # Define Suricata compatible rules
      rules_string = <<EOF
pass tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Allowing outbound TCP"; sid:1; rev:1;)
EOF
    }
  }

  tags = {
    Environment = "production"
  }
}

# Create Network Firewall Policy with a rule group
resource "aws_networkfirewall_policy" "pass_policy" {
  provider = aws.pass_aws
  name     = "pass-policy"

  firewall_policy {
    # Define default actions for stateless rules
    stateless_default_actions = ["aws:forward_to_sfe"]
    stateless_fragment_default_actions = ["aws:forward_to_sfe"]
    
    # Associate stateful rule group
    stateful_rule_group_reference {
      resource_arn = aws_networkfirewall_rule_group.pass_rule_group.arn
    }
  }

  tags = {
    Environment = "production"
  }
}
