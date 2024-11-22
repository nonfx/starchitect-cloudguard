package rules.gcp_dns_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "2.12",
	"title": "Ensure That Cloud DNS Logging Is Enabled for All VPC Networks",
	"description": "Cloud DNS logging records the queries from the name servers within your VPC to Stackdriver. Logged queries can come from Compute Engine VMs, GKE containers, or other GCP resources provisioned within the VPC.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.12"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all VPC networks and DNS policies
networks = fugue.resources("google_compute_network")

dns_policies = fugue.resources("google_dns_policy")

# Helper function to check if network has DNS logging enabled
has_dns_logging(network) {
	policy := dns_policies[_]
	policy.enable_logging == true
	net := policy.networks[_]
	net.network_url == network.id
}

# Allow if network has DNS logging enabled
policy[p] {
	network := networks[_]
	has_dns_logging(network)
	p = fugue.allow_resource(network)
}

# Deny if network exists but DNS logging is not enabled
policy[p] {
	network := networks[_]
	not has_dns_logging(network)
	p = fugue.deny_resource_with_message(network, sprintf("Cloud DNS logging is not enabled for VPC network: %s", [network.name]))
}
