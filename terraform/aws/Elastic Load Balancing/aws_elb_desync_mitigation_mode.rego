package rules.elb_desync_mitigation_mode

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.12",
	"title": "Application Load Balancer should be configured with defensive or strictest desync mitigation mode",
	"description": "Application Load Balancers must be configured with defensive or strictest desync mitigation mode to prevent HTTP desync attacks.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.12"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Application Load Balancers
albs = fugue.resources("aws_lb")

# Valid desync mitigation modes
valid_modes = ["defensive", "strictest"]

# Check if ALB has valid desync mitigation mode
has_valid_mode(alb) {
	desync_mitigation_mode = alb.desync_mitigation_mode
	desync_mitigation_mode == valid_modes[_]
}

# Allow if ALB has valid desync mitigation mode
policy[p] {
	alb := albs[_]
	has_valid_mode(alb)
	p = fugue.allow_resource(alb)
}

# Deny if ALB doesn't have valid desync mitigation mode
policy[p] {
	alb := albs[_]
	not has_valid_mode(alb)
	p = fugue.deny_resource_with_message(
		alb,
		sprintf("Application Load Balancer '%s' must be configured with defensive or strictest desync mitigation mode", [alb.name]),
	)
}
