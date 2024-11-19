package rules.networkfirewall_stateless_rule_group_not_empty

import data.fugue

__rego__metadoc__ := {
	"id": "NetworkFirewall.6",
	"title": "Stateless Network Firewall rule group should not be empty",
	"description": "AWS Network Firewall stateless rule groups must contain rules to effectively process and filter VPC traffic.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_NetworkFirewall.6"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

# Define resource type for multiple resources
resource_type := "MULTIPLE"

# Get all Network Firewall rule groups
rule_groups = fugue.resources("aws_networkfirewall_rule_group")

# Helper function to check if rule group has rules
has_rules(group) {
	group.rule_group[_].rules_source[_].stateless_rules_and_custom_actions[_].stateless_rule[_]
}

# Allow rule groups that have rules
policy[p] {
	group := rule_groups[_]
	group.type == "STATELESS"
	has_rules(group)
	p = fugue.allow_resource(group)
}

# Deny rule groups that don't have rules
policy[p] {
	group := rule_groups[_]
	group.type == "STATELESS"
	not has_rules(group)
	p = fugue.deny_resource_with_message(group, "Stateless Network Firewall rule group must contain at least one rule")
}
