package rules.elb_multiple_az

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.10",
	"title": "Classic Load Balancer should span multiple Availability Zones",
	"description": "Classic Load Balancers must be configured to operate across multiple Availability Zones for high availability and fault tolerance.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.10"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

# Get all Classic Load Balancers
elbs = fugue.resources("aws_elb")

# Minimum required number of Availability Zones
min_az_count = 2

# Check if ELB has sufficient AZs
has_sufficient_azs(elb) {
	count(elb.availability_zones) >= min_az_count
}

# Allow if ELB spans sufficient AZs
policy[p] {
	elb := elbs[_]
	has_sufficient_azs(elb)
	p = fugue.allow_resource(elb)
}

# Deny if ELB doesn't span sufficient AZs
policy[p] {
	elb := elbs[_]
	not has_sufficient_azs(elb)
	p = fugue.deny_resource_with_message(
		elb,
		sprintf(
			"Classic Load Balancer '%s' must span at least %d Availability Zones for high availability. Current AZ count: %d",
			[elb.name, min_az_count, count(elb.availability_zones)],
		),
	)
}
