package rules.aws_lambda_unique_iam_role

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "AWS_Lambda_4.5",
	"title": "Ensure every Lambda function has its own IAM Role",
	"description": "Every Lambda function should have a one to one IAM execution role and the roles should not be shared between functions.",
	"custom": {"controls":{"CIS-AWS-Compute-Services-Benchmark_v1.0.0":["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.5"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

lambda_functions := fugue.resources("aws_lambda_function")

# Helper function to get the role ARN from a Lambda function
get_role_arn(function) = role_arn {
	role_arn := function.role
}

# Check if a role is unique across all Lambda functions
is_role_unique(function) {
	role_arn := get_role_arn(function)
	count([1 | f := lambda_functions[_]; get_role_arn(f) == role_arn]) == 1
}

policy[p] {
	function := lambda_functions[_]
	is_role_unique(function)
	p = fugue.allow_resource(function)
}

policy[p] {
	function := lambda_functions[_]
	not is_role_unique(function)
	msg := sprintf("Lambda function '%s' shares its IAM role with another function. Each Lambda function should have a unique IAM role.", [function.function_name])
	p = fugue.deny_resource_with_message(function, msg)
}
