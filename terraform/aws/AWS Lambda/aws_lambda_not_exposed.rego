package rules.aws_lambda_not_exposed

import data.aws.lambda.permissions_library as lib
import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "4.6",
	"title": "Ensure Lambda functions are not exposed to everyone",
	"description": "A publicly accessible Amazon Lambda function is open to the public and can be reviewed by anyone. To protect against unauthorized users that are sending requests to invoke these functions they need to be changed so they are not exposed to the public.",
	"custom": {"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.6"]}},
}

resource_type := "MULTIPLE"

message = "Lambda functions should not be exposed to everyone"

valid_permission(permission) {
	is_string(permission.principal)
	permission.principal != "*"
}

policy[j] {
	func = lib.funcs_by_key[k][_]
	not lib.perm_by_key[k]
	j = fugue.allow_resource(func)
}

policy[j] {
	permission = lib.permissions[_]
	valid_permission(permission)
	k = lib.permission_key(permission)
	f = lib.funcs_by_key[k][_]
	j = fugue.allow_resource(f)
}

policy[j] {
	permission = lib.permissions[_]
	not valid_permission(permission)
	k = lib.permission_key(permission)
	f = lib.funcs_by_key[k][_]
	j = fugue.deny_resource_with_message(f, message)
}
