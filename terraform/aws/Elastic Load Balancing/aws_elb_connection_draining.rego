package rules.elb_connection_draining

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.7",
	"title": "Classic Load Balancers should have connection draining enabled",
	"description": "This control checks if Classic Load Balancers have connection draining enabled to ensure graceful handling of deregistering or unhealthy instances.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.7"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all Classic Load Balancers
clbs = fugue.resources("aws_elb")

# Helper to check if connection draining is enabled
is_connection_draining_enabled(clb) {
	clb.connection_draining == true
}

# Allow CLBs with connection draining enabled
policy[p] {
	clb := clbs[_]
	is_connection_draining_enabled(clb)
	p = fugue.allow_resource(clb)
}

# Deny CLBs without connection draining
policy[p] {
	clb := clbs[_]
	not is_connection_draining_enabled(clb)
	p = fugue.deny_resource_with_message(clb, "Connection draining must be enabled for Classic Load Balancer")
}
