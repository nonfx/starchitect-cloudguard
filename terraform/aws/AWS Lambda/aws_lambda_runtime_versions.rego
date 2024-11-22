package rules.aws_lambda_runtime_versions

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "4.11",
	"title": "Ensure that the runtime environment versions used for your Lambda functions do not have end of support dates",
	"description": "Always using a recent version of the execution environment configured for your Amazon Lambda functions adheres to best practices for the newest software features, the latest security patches and bug fixes, and performance and reliability",
	"custom": {"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.11"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_lambda_functions := fugue.resources("aws_lambda_function")

#TODO fetch runtimes dynamically. rego doesn't support fetching dynamic items. Need to create github actions with python utility to generate latest supported runtimes from AWS
#https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html
supported_runtimes := [
	"nodejs20.x",
	"nodejs18.x",
	"python3.12",
	"python3.11",
	"python3.10",
	"python3.9",
	"python3.8",
	"java21",
	"java17",
	"java11",
	"java8.al2",
	"dotnet8",
	"dotnet6",
	"ruby3.3",
	"ruby3.2",
	"provided.al2023",
	"provided.al2",
]

is_supported_runtime(runtime) {
	runtime in supported_runtimes
}

policy[p] {
	resource := aws_lambda_functions[_]
	is_supported_runtime(resource.runtime)
	p := fugue.allow_resource(resource)
}

policy[p] {
	resource := aws_lambda_functions[_]
	not is_supported_runtime(resource.runtime)
	msg := sprintf("Lambda function '%s' is using an unsupported runtime: %s", [resource.function_name, resource.runtime])
	p := fugue.deny_resource_with_message(resource, msg)
}
