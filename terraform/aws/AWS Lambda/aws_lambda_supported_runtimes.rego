package rules.lambda_supported_runtimes

import data.fugue

__rego__metadoc__ := {
	"id": "Lambda.2",
	"title": "Lambda functions should use supported runtimes",
	"description": "This control checks if Lambda functions use supported runtimes. Functions with unsupported or deprecated runtimes may pose security risks due to lack of updates.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Lambda.2"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

lambda_functions = fugue.resources("aws_lambda_function")

# List of supported runtimes
supported_runtimes = [
	"dotnet8",
	"dotnet6",
	"java21",
	"java17",
	"java11",
	"nodejs20.x",
	"nodejs18.x",
	"nodejs16.x",
	"provided",
	"provided.al2",
	"python3.12",
	"python3.11",
	"python3.10",
	"python3.9",
	"ruby3.2",
]

# Helper to check if runtime is supported
is_supported_runtime(function) {
	function.package_type != "Image"
	supported_runtimes[_] == function.runtime
}

# Allow functions using supported runtimes or Image package type
policy[p] {
	function := lambda_functions[_]
	function.package_type == "Image"
	p = fugue.allow_resource(function)
}

policy[p] {
	function := lambda_functions[_]
	is_supported_runtime(function)
	p = fugue.allow_resource(function)
}

# Deny functions using unsupported runtimes
policy[p] {
	function := lambda_functions[_]
	function.package_type != "Image"
	not is_supported_runtime(function)
	p = fugue.deny_resource_with_message(function, sprintf("Lambda function uses unsupported runtime '%s'. Use one of the supported runtimes: %s", [function.runtime, concat(", ", supported_runtimes)]))
}
