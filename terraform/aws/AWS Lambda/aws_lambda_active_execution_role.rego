package rules.aws_lambda_active_execution_role

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "AWS_LAMBDA_4.7",
	"title": "Ensure Lambda functions are referencing active execution roles",
	"description": "In order to have the necessary permissions to access the AWS cloud services and resources Amazon Lambda functions should be associated with active(available) execution roles.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.7"]},
		"severity": "Low",
	},
}

resource_type := "MULTIPLE"

lambda_functions := fugue.resources("aws_lambda_function")

iam_roles := fugue.resources("aws_iam_role")

# Check if the IAM role is active
active_role(role) {
	role.name != ""
}

# Validate if the Lambda function is associated with an active IAM role
valid_lambda(lambda) {
	some role in iam_roles
	active_role(role)
}

# Allow Lambda functions with active execution roles
policy[p] {
	lambda := lambda_functions[_]
	valid_lambda(lambda)
	p = fugue.allow_resource(lambda)
}

# Deny Lambda functions without active execution roles
policy[p] {
	lambda := lambda_functions[_]
	not valid_lambda(lambda)
	msg := sprintf("Lambda function '%s' is not associated with an active execution role", [lambda.function_name])
	p = fugue.deny_resource_with_message(lambda, msg)
}
