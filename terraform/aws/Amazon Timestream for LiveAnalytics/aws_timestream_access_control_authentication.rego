package rules.aws_timestream_access_control_authentication

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "10.4",
	"title": "Ensure Access Control and Authentication is Enabled",
	"description": "Utilize AWS Identity and Access Management (IAM) to control access to your Amazon Timestream resources. Define IAM policies that grant or deny permissions for specific Timestream actions and resources.",
	"custom": {"controls": {"CIS-AWS-Timestream-Services-Benchmark_v1.0.0": [
		"CIS-AWS-Timestream-Services-Benchmark_v1.0.0_10.4.a",
		"CIS-AWS-Timestream-Services-Benchmark_v1.0.0_10.4.b",
	]}},
}

resource_type := "MULTIPLE"

timestreamwrite_databases := fugue.resources("aws_timestreamwrite_database")

iam_policies := fugue.resources("aws_iam_policy")

iam_role_policies := fugue.resources("aws_iam_role_policy")

iam_user_policies := fugue.resources("aws_iam_user_policy")

iam_group_policies := fugue.resources("aws_iam_group_policy")

as_array(x) = [x] {
	not is_array(x)
}

else = x

fgac_not_followed(policy_resource, tsdb) {
	policy := json.unmarshal(policy_resource.policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	resources = as_array(statement.Resource)
	resource = resources[_]
	contains(resource, tsdb.database_name)
	actions = as_array(statement.Action[_])
	action = actions[_]
	action == "*"
}

fgac_not_followed(policy_resource, tsdb) {
	policy := json.unmarshal(policy_resource.policy)
	statement := policy.Statement[_]
	statement.Effect == "Allow"
	resources = as_array(statement.Resource)
	resource = resources[_]
	contains(resource, tsdb.database_name)
	actions = as_array(statement.Action[_])
	action = actions[_]
	action == "timestream:*"
}

# rule to check if aws_iam_policy is fine grained
policy[p] {
	timestreamwrite_database = timestreamwrite_databases[_]
	iam_policy := iam_policies[_]
	not fgac_not_followed(iam_policy, timestreamwrite_database)
	p := fugue.allow_resource(timestreamwrite_database)
}

policy[p] {
	timestreamwrite_database = timestreamwrite_databases[_]
	iam_policy := iam_policies[_]
	fgac_not_followed(iam_policy, timestreamwrite_database)
	msg := sprintf("Access Control is not implemented on this IAM policy for %s", [timestreamwrite_database.database_name])
	p := fugue.deny_resource_with_message(timestreamwrite_database, msg)
}

# rule to check if aws_iam_role_policy is fine grained
policy[p] {
	timestreamwrite_database = timestreamwrite_databases[_]
	iam_role_policy := iam_role_policies[_]
	not fgac_not_followed(iam_role_policy, timestreamwrite_database)
	p := fugue.allow_resource(timestreamwrite_database)
}

policy[p] {
	timestreamwrite_database = timestreamwrite_databases[_]
	iam_role_policy := iam_role_policies[_]
	fgac_not_followed(iam_role_policy, timestreamwrite_database)
	msg := sprintf("Access Control is not implemented on this IAM role policy for %s", [timestreamwrite_database.database_name])
	p := fugue.deny_resource_with_message(timestreamwrite_database, msg)
}

# rule to check if aws_iam_user_policy is fine grained
policy[p] {
	timestreamwrite_database = timestreamwrite_databases[_]
	iam_user_policy := iam_user_policies[_]
	not fgac_not_followed(iam_user_policy, timestreamwrite_database)
	p := fugue.allow_resource(timestreamwrite_database)
}

policy[p] {
	timestreamwrite_database = timestreamwrite_databases[_]
	iam_user_policy := iam_user_policies[_]
	fgac_not_followed(iam_user_policy, timestreamwrite_database)
	msg := sprintf("Access Control is not implemented on this IAM user policy for %s", [timestreamwrite_database.database_name])
	p := fugue.deny_resource_with_message(timestreamwrite_database, msg)
}

# rule to check if aws_iam_group_policy is fine grained
policy[p] {
	timestreamwrite_database = timestreamwrite_databases[_]
	iam_group_policy := iam_group_policies[_]
	not fgac_not_followed(iam_group_policy, timestreamwrite_database)
	p := fugue.allow_resource(timestreamwrite_database)
}

policy[p] {
	timestreamwrite_database = timestreamwrite_databases[_]
	iam_group_policy := iam_group_policies[_]
	fgac_not_followed(iam_group_policy, timestreamwrite_database)
	msg := sprintf("Access Control is not implemented on this IAM group policy for %s", [timestreamwrite_database.database_name])
	p := fugue.deny_resource_with_message(timestreamwrite_database, msg)
}
