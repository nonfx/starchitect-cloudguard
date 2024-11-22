package rules.network_firewall_deletion_protection

import data.fugue

__rego__metadoc__ := {
	"id": "NetworkFirewall.9",
	"title": "Network Firewall firewalls should have deletion protection enabled",
	"description": "AWS Network Firewall firewalls must have deletion protection enabled to prevent accidental deletion and enhance security.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_NetworkFirewall.9"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Network Firewall resources
firewalls = fugue.resources("aws_networkfirewall_firewall")

# Allow if firewall has deletion protection enabled
policy[p] {
	firewall := firewalls[_]
	firewall.delete_protection == true
	p = fugue.allow_resource(firewall)
}

# Deny if firewall does not have deletion protection enabled
policy[p] {
	firewall := firewalls[_]
	not firewall.delete_protection
	p = fugue.deny_resource_with_message(
		firewall,
		"Network Firewall must have deletion protection enabled to prevent accidental deletion",
	)
}
