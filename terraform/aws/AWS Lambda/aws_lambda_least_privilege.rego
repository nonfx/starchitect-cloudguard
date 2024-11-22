package rules.aws_lambda_least_privilege

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "4.4",
	"title": "Ensure least privilege is used with Lambda function access",
	"description": "Lambda is fully integrated with IAM, allowing you to control precisely what each Lambda function can do within the AWS Cloud. As you develop a Lambda function, you expand the scope of this policy to enable access to other resources. For example, for a function that processes objects put into an S3 bucket, it requires read access to objects stored in that bucket. Do not grant the function broader permissions to write or delete data, or operate in other buckets.",
	"custom": {
		"severity": "Medium",
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_4.4"]},
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

lambda_functions := fugue.resources("aws_lambda_function")

iam_roles := fugue.resources("aws_iam_role")

iam_role_policies := fugue.resources("aws_iam_role_policy")

# Helper function to check if a policy document has overly permissive actions
is_overly_permissive(policy_doc) {
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	action := statement.Action[_]

	# PASS WITH ALERT:NEED USER TO TELL WHICH PERMISSIONS ARE NEEDED
	contains(action, "*")
}

# Check if a Lambda function's role has overly permissive policies
has_overly_permissive_policy(func) {
	role := iam_roles[func.role]
	policy := iam_role_policies[_]
	policy.role == role.id
	is_overly_permissive(json.unmarshal(policy.policy))
}

policy[p] {
	func := lambda_functions[_]
	has_overly_permissive_policy(func)
	msg := sprintf("Lambda function '%s' has an overly permissive IAM role policy. Ensure least privilege access is used.", [func.function_name])
	p = fugue.deny_resource_with_message(func, msg)
}

policy[p] {
	func := lambda_functions[_]
	not has_overly_permissive_policy(func)
	p = fugue.allow_resource(func)
}
