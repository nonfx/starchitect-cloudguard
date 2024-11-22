package rules.aws_dynamodb_fgac_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "4.2",
	"title": "Ensure Fine-Grained Access Control is implemented",
	"description": "Fine-Grained Access Control (FGAC) on Amazon DynamoDB allows you to control access to data at the row level. Using IAM policies, you can restrict access based on the content within the request.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_4.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

dynamodb_table_policies := fugue.resources("aws_dynamodb_table_policy")

iam_policies := fugue.resources("aws_iam_policy")

iam_role_policies := fugue.resources("aws_iam_role_policy")

iam_user_policies := fugue.resources("aws_iam_user_policy")

iam_group_policies := fugue.resources("aws_iam_group_policy")

as_array(x) = [x] {
	not is_array(x)
}

else = x

fgac_not_followed(policy_resource) {
	policy := json.unmarshal(policy_resource.policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	actions = as_array(statement.Action[_])
	action = actions[_]
	action == "*"
}

fgac_not_followed(policy_resource) {
	policy := json.unmarshal(policy_resource.policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	actions = as_array(statement.Action[_])
	action = actions[_]
	action == "dynamodb:*"
}

policy[p] {
	dynamodb_table_policy := dynamodb_table_policies[_]
	not fgac_not_followed(dynamodb_table_policy)
	p := fugue.allow_resource(dynamodb_table_policy)
}

policy[p] {
	dynamodb_table_policy := dynamodb_table_policies[_]
	fgac_not_followed(dynamodb_table_policy)
	p := fugue.deny_resource_with_message(dynamodb_table_policy, "Fine-Grained Access Control is not implemented on this DynamoDB table.")
}

# rule to check if aws_iam_policy is fine grained
policy[p] {
	iam_policy := iam_policies[_]
	not fgac_not_followed(iam_policy)
	p := fugue.allow_resource(iam_policy)
}

policy[p] {
	iam_policy := iam_policies[_]
	fgac_not_followed(iam_policy)
	p := fugue.deny_resource_with_message(iam_policy, "Fine-Grained Access Control is not implemented on this IAM policy.")
}

# rule to check if aws_iam_role_policy is fine grained
policy[p] {
	iam_role_policy := iam_role_policies[_]
	not fgac_not_followed(iam_role_policy)
	p := fugue.allow_resource(iam_role_policy)
}

policy[p] {
	iam_role_policy := iam_role_policies[_]
	fgac_not_followed(iam_role_policy)
	p := fugue.deny_resource_with_message(iam_role_policy, "Fine-Grained Access Control is not implemented on this IAM role policy.")
}

# rule to check if aws_iam_user_policy is fine grained
policy[p] {
	iam_user_policy := iam_user_policies[_]
	not fgac_not_followed(iam_user_policy)
	p := fugue.allow_resource(iam_user_policy)
}

policy[p] {
	iam_user_policy := iam_user_policies[_]
	fgac_not_followed(iam_user_policy)
	p := fugue.deny_resource_with_message(iam_user_policy, "Fine-Grained Access Control is not implemented on this IAM user policy.")
}

# rule to check if aws_iam_group_policy is fine grained
policy[p] {
	iam_group_policy := iam_group_policies[_]
	not fgac_not_followed(iam_group_policy)
	p := fugue.allow_resource(iam_group_policy)
}

policy[p] {
	iam_group_policy := iam_group_policies[_]
	fgac_not_followed(iam_group_policy)
	p := fugue.deny_resource_with_message(iam_group_policy, "Fine-Grained Access Control is not implemented on this IAM group policy.")
}
