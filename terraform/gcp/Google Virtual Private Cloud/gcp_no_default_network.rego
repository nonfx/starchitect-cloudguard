package rules.gcp_no_default_network

import data.fugue

__rego__metadoc__ := {
	"id": "3.1",
	"title": "Ensure That the Default Network Does Not Exist in a Project",
	"description": "To prevent use of default network a project should not have a default network. Default networks have preconfigured firewall rules and automatic subnet creation which may not align with security requirements.",
	"custom": {
		"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.1"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

# Get all VPC networks
networks = fugue.resources("google_compute_network")

# Check if network is a default network
is_default_network(network) {
	network.name == "default"
}

# Deny if default network exists
policy[p] {
	network := networks[_]
	is_default_network(network)
	p = fugue.deny_resource_with_message(
		network,
		"Default network detected in project. Default networks should be deleted as they create preconfigured firewall rules that may not align with security requirements.",
	)
}

# Allow if network is not default
policy[p] {
	network := networks[_]
	not is_default_network(network)
	p = fugue.allow_resource(network)
}
