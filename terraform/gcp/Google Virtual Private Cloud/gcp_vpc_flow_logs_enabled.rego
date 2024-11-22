package rules.gcp_vpc_flow_logs_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "3.8",
	"title": "Ensure that VPC Flow Logs is Enabled for Every Subnet in a VPC Network",
	"description": "VPC Flow Logs must be enabled on all business-critical VPC subnets to capture and monitor IP traffic for security and analysis purposes.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_3.8"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all VPC subnets
subnets = fugue.resources("google_compute_subnetwork")

# Helper to check if log config is properly configured
is_valid_log_config(subnet) {
	subnet.log_config[_].aggregation_interval != null
	subnet.log_config[_].flow_sampling == 1
	subnet.log_config[_].metadata != null
}

# Helper to check if subnet is eligible for flow logs
is_eligible_subnet(subnet) {
	not subnet.purpose == "REGIONAL_MANAGED_PROXY"
	not subnet.purpose == "GLOBAL_MANAGED_PROXY"
}

# Allow subnets with proper flow logs configuration
policy[p] {
	subnet := subnets[_]
	is_eligible_subnet(subnet)
	is_valid_log_config(subnet)
	p = fugue.allow_resource(subnet)
}

# Deny eligible subnets without flow logs
policy[p] {
	subnet := subnets[_]
	is_eligible_subnet(subnet)
	not is_valid_log_config(subnet)
	p = fugue.deny_resource_with_message(subnet, "VPC Flow Logs must be enabled with 5-second aggregation interval, 100% sampling rate, and include all metadata")
}
