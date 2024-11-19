package rules.networkfirewall_default_fragment_action

import data.fugue

__rego__metadoc__ := {
	"id": "NetworkFirewall.5",
	"title": "The default stateless action for Network Firewall policies should be drop or forward for fragmented packets",
	"description": "Network Firewall policies must configure default stateless actions as drop or forward for fragmented packets to prevent unintended traffic.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_NetworkFirewall.5"]}, "severity": "Medium", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

# Define resource type
resource_type := "MULTIPLE"

# Get all Network Firewall policies
firewall_policies = fugue.resources("aws_networkfirewall_policy")

# Define valid fragment actions
valid_fragment_actions := {"aws:drop", "aws:forward_to_sfe"}

# Function to check if fragment action is valid
is_valid_fragment_action(policy) {
	action := policy.firewall_policy.stateless_fragment_default_actions[_]
	valid_fragment_actions[action]
}

# Allow policy if fragment action is valid
policy[p] {
	policy := firewall_policies[_]
	is_valid_fragment_action(policy)
	p = fugue.allow_resource(policy)
}

# Deny policy if fragment action is invalid
policy[p] {
	policy := firewall_policies[_]
	not is_valid_fragment_action(policy)
	p = fugue.deny_resource_with_message(
		policy,
		"Network Firewall policy must set default stateless fragment action to either 'aws:drop' or 'aws:forward_to_sfe'",
	)
}
