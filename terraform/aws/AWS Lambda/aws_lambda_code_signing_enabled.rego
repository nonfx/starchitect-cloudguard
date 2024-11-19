package rules.aws_lambda_code_signing_enabled

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "AWS_Lambda_4.8",
	"title": "Ensure that Code Signing is enabled for Lambda functions",
	"description": "Ensure that all your Amazon Lambda functions are configured to use the Code Signing feature in order to restrict the deployment of unverified code.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.8"]},
		"severity": "Low",
	},
}

resource_type := "MULTIPLE"

lambda_functions := fugue.resources("aws_lambda_function")

# Check if Code Signing is enabled for a Lambda function
code_signing_enabled(lambda) {
	lambda.code_signing_config_arn != null
	lambda.code_signing_config_arn != ""
}

# Allow Lambda functions with Code Signing enabled
policy[p] {
	lambda := lambda_functions[_]
	code_signing_enabled(lambda)
	p = fugue.allow_resource(lambda)
}

# Deny Lambda functions without Code Signing enabled
policy[p] {
	lambda := lambda_functions[_]
	not code_signing_enabled(lambda)
	msg := sprintf("Lambda function '%s' does not have Code Signing enabled", [lambda.function_name])
	p = fugue.deny_resource_with_message(lambda, msg)
}
