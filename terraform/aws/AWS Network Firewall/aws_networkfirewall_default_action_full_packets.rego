package rules.networkfirewall_default_action_full_packets

import data.fugue

__rego__metadoc__ := {
	"id": "NetworkFirewall.4",
	"title": "The default stateless action for Network Firewall policies should be drop or forward for full packets",
	"description": "Network Firewall policies must configure default stateless actions as drop or forward for full packets to prevent unintended traffic.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_NetworkFirewall.4"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Network Firewall policies
firewall_policies = fugue.resources("aws_networkfirewall_firewall_policy")

# Define allowed default actions
allowed_actions = ["aws:drop", "aws:forward_to_sfe"]

# Helper to check if default action is valid
is_valid_default_action(policy) {
	policy.firewall_policy[_].stateless_default_actions[_] == allowed_actions[_]
}

# Allow if default action is drop or forward
policy[p] {
	policy := firewall_policies[_]
	is_valid_default_action(policy)
	p = fugue.allow_resource(policy)
}

# Deny if default action is not drop or forward
policy[p] {
	policy := firewall_policies[_]
	not is_valid_default_action(policy)
	p = fugue.deny_resource_with_message(policy, "Network Firewall policy default stateless action for full packets must be set to drop or forward ")
}
