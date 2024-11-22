package rules.lambda_function_no_public_access

import data.fugue

__rego__metadoc__ := {
	"id": "Lambda.1",
	"title": "Lambda function policies should prohibit public access",
	"description": "This control checks if Lambda function's resource-based policy prohibits public access and implements proper AWS:SourceAccount conditions for S3 invocations.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Lambda.1"]}, "severity": "Critical"},
}

resource_type := "MULTIPLE"

lambda_functions = fugue.resources("aws_lambda_function")

lambda_permissions = fugue.resources("aws_lambda_permission")

# Helper to check if principal is public
is_public_principal(principal) {
	principal == "*"
}

is_public_principal(principal) {
	principal == {"AWS": "*"}
}

# Helper to check if S3 invocation has proper source account condition
has_valid_s3_condition(permission) {
	permission.principal == "s3.amazonaws.com"
	permission.source_account != null
}

# Check if function has public permissions
has_public_access(function_name) {
	permission := lambda_permissions[_]
	permission.function_name == function_name
	is_public_principal(permission.principal)
	not has_valid_s3_condition(permission)
}

policy[p] {
	function := lambda_functions[_]
	not has_public_access(function.function_name)
	p = fugue.allow_resource(function)
}

policy[p] {
	function := lambda_functions[_]
	has_public_access(function.function_name)
	p = fugue.deny_resource_with_message(function, "Lambda function has public access permissions or missing AWS:SourceAccount condition for S3 invocations")
}
