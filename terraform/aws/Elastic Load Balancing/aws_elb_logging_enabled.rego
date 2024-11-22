package rules.elb_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "ELB.5",
	"title": "Load Balancer Logging Must Be Enabled",
	"description": "Ensures that all Application and Classic Load Balancers have logging enabled",
	"custom": {"severity":"Medium","controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_ELB.5"]},"author":"Starchitect Agent"},
}

# Define resource types to evaluate
resource_type := "MULTIPLE"

# Get all load balancer resources
classic_lbs = fugue.resources("aws_elb")

application_lbs = fugue.resources("aws_lb")

# Helper function to check if logging is enabled
is_logging_enabled(lb) {
	lb.access_logs[_].enabled == true
}

# Allow rule for classic load balancers with logging enabled
policy[p] {
	lb := classic_lbs[_]
	is_logging_enabled(lb)
	p = fugue.allow_resource(lb)
}

# Allow rule for application load balancers with logging enabled
policy[p] {
	lb := application_lbs[_]
	is_logging_enabled(lb)
	p = fugue.allow_resource(lb)
}

# Deny rule for classic load balancers without logging
policy[p] {
	lb := classic_lbs[_]
	not is_logging_enabled(lb)
	p = fugue.deny_resource_with_message(
		lb,
		"Classic Load Balancer must have access logging enabled",
	)
}

# Deny rule for application load balancers without logging
policy[p] {
	lb := application_lbs[_]
	not is_logging_enabled(lb)
	p = fugue.deny_resource_with_message(
		lb,
		"Application Load Balancer must have access logging enabled",
	)
}
