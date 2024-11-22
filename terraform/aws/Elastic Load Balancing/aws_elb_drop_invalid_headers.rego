package rules.elb_drop_invalid_headers

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.4",
	"title": "Application Load Balancer should be configured to drop invalid http headers",
	"description": "This control checks if Application Load Balancers are configured to drop invalid HTTP headers to prevent HTTP desync attacks and enhance security.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.4"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all ALBs
albs = fugue.resources("aws_lb")

# Helper to check if invalid header dropping is enabled
is_invalid_header_dropping_enabled(alb) {
	alb.drop_invalid_header_fields == true
}

# Allow if ALB has invalid header dropping enabled
policy[p] {
	alb := albs[_]
	is_invalid_header_dropping_enabled(alb)
	p = fugue.allow_resource(alb)
}

# Deny if ALB does not have invalid header dropping enabled
policy[p] {
	alb := albs[_]
	not is_invalid_header_dropping_enabled(alb)
	p = fugue.deny_resource_with_message(alb, "Application Load Balancer must be configured to drop invalid HTTP headers")
}
