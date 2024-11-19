package rules.elb_v2_multiple_az

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.13",
	"title": "Application, Network and Gateway Load Balancers should span multiple Availability Zones",
	"description": "Application, Network, and Gateway Load Balancers must be configured with multiple Availability Zones for high availability and fault tolerance.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.13"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all ELBv2 Load Balancers
lbs = fugue.resources("aws_lb")

# Minimum required number of AZs
min_az_count = 2

# Check if load balancer has sufficient AZs
has_sufficient_azs(lb) {
	count(lb.subnets) >= min_az_count
}

# Allow if LB has sufficient AZs
policy[p] {
	lb := lbs[_]
	has_sufficient_azs(lb)
	p = fugue.allow_resource(lb)
}

# Deny if LB doesn't have sufficient AZs
policy[p] {
	lb := lbs[_]
	not has_sufficient_azs(lb)
	p = fugue.deny_resource_with_message(
		lb,
		sprintf("Load Balancer '%s' must be configured with at least %d Availability Zones for high availability", [lb.name, min_az_count]),
	)
}
