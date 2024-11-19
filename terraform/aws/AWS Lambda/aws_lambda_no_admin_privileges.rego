package rules.aws_lambda_no_admin_privileges

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "AWS_LAMBDA_4.9",
	"title": "Ensure least privilege is used with Lambda function access",
	"description": "Lambda is fully integrated with IAM, allowing you to control precisely what each Lambda function can do within the AWS Cloud. As you develop a Lambda function, you expand the scope of this policy to enable access to other resources. For example, for a function that processes objects put into an S3 bucket, it requires read access to objects stored in that bucket. Do not grant the function broader permissions to write or delete data, or operate in other buckets.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.9"]},
		"severity": "Low",
	},
}

resource_type := "MULTIPLE"

lambda_functions := fugue.resources("aws_lambda_function")

iam_roles := fugue.resources("aws_iam_role")

iam_role_policies := fugue.resources("aws_iam_role_policy")

# Helper function to check if a policy document has overly permissive actions
has_admin_access(policy_doc) {
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	action := statement.Action[_]
	resource := statement.Resource[_]
	contains(action, "*")
	contains(resource, "*")
}

# Check if a Lambda function's role has overly permissive policies
has_overly_permissive_policy(func) {
	role := iam_roles[func.role]
	policy := iam_role_policies[_]
	policy.role == role.id
	has_admin_access(json.unmarshal(policy.policy))
}

policy[p] {
	func := lambda_functions[_]
	has_overly_permissive_policy(func)
	msg := sprintf("Lambda function '%s' has administrative privileges", [func.function_name])
	p = fugue.deny_resource_with_message(func, msg)
}

policy[p] {
	func := lambda_functions[_]
	not has_overly_permissive_policy(func)
	p = fugue.allow_resource(func)
}
