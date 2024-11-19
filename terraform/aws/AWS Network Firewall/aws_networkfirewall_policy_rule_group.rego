package rules.networkfirewall_policy_rule_group

import data.fugue

__rego__metadoc__ := {
	"id": "NetworkFirewall.3",
	"title": "Network Firewall policies should have at least one rule group associated",
	"description": "Network Firewall policies must have at least one rule group associated to ensure proper traffic filtering and security.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_NetworkFirewall.3"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

# Define resource type for multiple resources
resource_type := "MULTIPLE"

# Get all Network Firewall policies
firewall_policies = fugue.resources("aws_networkfirewall_policy")

# Check if policy has stateful rule groups
has_stateful_rules(policy) {
	policy.firewall_policy[_].stateful_rule_group_reference[_]
}

# Check if policy has stateless rule groups
has_stateless_rules(policy) {
	policy.firewall_policy[_].stateless_rule_group_reference[_]
}

# Allow if policy has any rule groups
policy[p] {
	policy := firewall_policies[_]
	has_stateful_rules(policy)
	p = fugue.allow_resource(policy)
}

policy[p] {
	policy := firewall_policies[_]
	has_stateless_rules(policy)
	p = fugue.allow_resource(policy)
}

# Deny if policy has no rule groups
policy[p] {
	policy := firewall_policies[_]
	not has_stateful_rules(policy)
	not has_stateless_rules(policy)
	p = fugue.deny_resource_with_message(policy, "Network Firewall policy must have at least one stateful or stateless rule group associated")
}
