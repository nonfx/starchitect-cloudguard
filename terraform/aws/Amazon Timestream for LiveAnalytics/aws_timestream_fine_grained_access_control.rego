package rules.aws_timestream_fine_grained_access_control

import data.fugue

__rego__metadoc__ := {
	"id": "10.5",
	"title": "Ensure Fine-Grained Access Control is Enabled",
	"description": "Leverage Timestream's fine-grained access control capabilities to control table or row level access. Define access policies that limit access to specific tables, columns, or rows based on user roles or conditions. Implement data filtering and row-level security to restrict access to sensitive information",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_10.5"]},"author":"Starchitect Agent"},
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
	contains(resource, "*")
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
	msg := sprintf("Fine-Grained Access Control is not implemented on this IAM  policy for %s", [timestreamwrite_database.database_name])
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
	msg := sprintf("Fine-Grained Access Control is not implemented on this IAM role policy for %s", [timestreamwrite_database.database_name])
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
	msg := sprintf("Fine-Grained Access Control is not implemented on this IAM user policy for %s", [timestreamwrite_database.database_name])
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
	msg := sprintf("Fine-Grained Access Control is not implemented on this IAM group policy for %s", [timestreamwrite_database.database_name])
	p := fugue.deny_resource_with_message(timestreamwrite_database, msg)
}
