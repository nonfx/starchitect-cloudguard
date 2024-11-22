package rules.lambda_vpc_multi_az

import data.fugue

__rego__metadoc__ := {
	"id": "Lambda.5",
	"title": "VPC Lambda functions should operate in multiple Availability Zones",
	"description": "This control checks if Lambda functions connected to VPC operate in multiple Availability Zones for high availability and fault tolerance.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Lambda.5"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

lambda_functions = fugue.resources("aws_lambda_function")

# Minimum required number of AZs
min_az_count = 2

# Helper to check if function is VPC-connected
is_vpc_function(func) {
	func.vpc_config != null
	count(func.vpc_config[_].subnet_ids) > 0
}

# Helper to count unique AZs from subnet IDs
get_az_count(func) {
	subnets := func.vpc_config[_].subnet_ids
	count(subnets) >= min_az_count
}

policy[p] {
	func := lambda_functions[_]
	not is_vpc_function(func)
	p = fugue.allow_resource(func)
}

policy[p] {
	func := lambda_functions[_]
	is_vpc_function(func)
	get_az_count(func)
	p = fugue.allow_resource(func)
}

policy[p] {
	func := lambda_functions[_]
	is_vpc_function(func)
	not get_az_count(func)
	p = fugue.deny_resource_with_message(func, sprintf("Lambda function must be configured with at least %v Availability Zones for high availability", [min_az_count]))
}
