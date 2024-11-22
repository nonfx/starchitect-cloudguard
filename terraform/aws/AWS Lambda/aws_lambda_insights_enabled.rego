package rules.aws_lambda_insights_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "4.2",
	"title": "Ensure Cloudwatch Lambda insights is enabled",
	"description": "Ensure that Amazon CloudWatch Lambda Insights is enabled for your Amazon Lambda functions for enhanced monitoring",
	"custom": {
		"severity": "Medium",
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.2"]},
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

lambda_functions := fugue.resources("aws_lambda_function")

insights_enabled(function) {
	layers := function.layers[_]
	contains(layers, ":layer:LambdaInsightsExtension:")
}

policy[p] {
	function := lambda_functions[_]
	insights_enabled(function)
	p = fugue.allow_resource(function)
}

policy[p] {
	function := lambda_functions[_]
	not insights_enabled(function)
	msg := sprintf("Lambda function '%s' does not have CloudWatch Lambda Insights enabled", [function.function_name])
	p = fugue.deny_resource_with_message(function, msg)
}
