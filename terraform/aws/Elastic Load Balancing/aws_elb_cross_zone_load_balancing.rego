package rules.elb_cross_zone_load_balancing

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.9",
	"title": "Classic Load Balancers should have cross-zone load balancing enabled",
	"description": "This control checks if Classic Load Balancers have cross-zone load balancing enabled to distribute traffic evenly across all enabled Availability Zones.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.9"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all Classic Load Balancers
clbs = fugue.resources("aws_elb")

# Helper to check if cross-zone load balancing is enabled
is_cross_zone_enabled(clb) {
	clb.cross_zone_load_balancing == true
}

# Allow CLBs with cross-zone load balancing enabled
policy[p] {
	clb := clbs[_]
	is_cross_zone_enabled(clb)
	p = fugue.allow_resource(clb)
}

# Deny CLBs without cross-zone load balancing
policy[p] {
	clb := clbs[_]
	not is_cross_zone_enabled(clb)
	p = fugue.deny_resource_with_message(clb, "Cross-zone load balancing must be enabled for Classic Load Balancer")
}
