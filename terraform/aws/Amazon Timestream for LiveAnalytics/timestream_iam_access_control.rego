package rules.timestream_iam_access_control

import data.fugue

as_array(x) = [x] {
	not is_array(x)
}

__rego__metadoc__ := {
	"id": "10.4",
	"title": "Ensure Access Control and Authentication is Enabled",
	"description": "Utilize AWS Identity and Access Management (IAM) to control access to your Amazon Timestream resources. Define IAM policies that grant or deny permissions for specific Timestream actions and resources.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_10.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

timestream_databases := fugue.resources("aws_timestreamwrite_database")

iam_roles := fugue.resources("aws_iam_role")

iam_policies := fugue.resources("aws_iam_policy")

iam_role_policy_attachments := fugue.resources("aws_iam_role_policy_attachment")

has_iam_role(database) {
	count(iam_roles) > 0
}

has_iam_policy(database) {
	count(iam_policies) > 0
}

has_iam_role_policy_attachment(database) {
	count(iam_role_policy_attachments) > 0
}

is_full_admin_policy(policy_resource) {
	policy := json.unmarshal(policy_resource.policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	actions = as_array(statement.Action[_])
	action = actions[_]
	contains(action, "*")
}

policy[p] {
	database := timestream_databases[_]
	has_iam_role(database)
	has_iam_policy(database)
	has_iam_role_policy_attachment(database)
	policy := iam_policies[_]
	not is_full_admin_policy(policy)
	p = fugue.allow_resource(database)
}

policy[p] {
	database := timestream_databases[_]
	not has_iam_role(database)
	msg := sprintf("Timestream database '%s' does not have an associated IAM role", [database.database_name])
	p = fugue.deny_resource_with_message(database, msg)
}

policy[p] {
	database := timestream_databases[_]
	not has_iam_policy(database)
	msg := sprintf("Timestream database '%s' does not have an associated IAM policy", [database.database_name])
	p = fugue.deny_resource_with_message(database, msg)
}

policy[p] {
	database := timestream_databases[_]
	not has_iam_role_policy_attachment(database)
	msg := sprintf("Timestream database '%s' does not have an IAM role policy attachment", [database.database_name])
	p = fugue.deny_resource_with_message(database, msg)
}

policy[p] {
	database := timestream_databases[_]
	has_iam_policy(database)
	policy := iam_policies[_]
	is_full_admin_policy(policy)
	msg := sprintf("Timestream database '%s' has an IAM policy with full admin access", [database.database_name])
	p = fugue.deny_resource_with_message(database, msg)
}
