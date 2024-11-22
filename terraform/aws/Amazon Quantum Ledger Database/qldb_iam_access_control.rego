package rules.qldb_iam_access_control

import data.fugue

as_array(x) = [x] {
	not is_array(x)
}

__rego__metadoc__ := {
	"id": "11.1",
	"title": "Ensure to Implement Identity and Access Management",
	"description": "This control is important because by having IAM roles implemented in the database it only allows certain people who are authenticated into the database to modify the database and would not give access to unauthorized personnel. This ensures that the data is being protected from any threat actor",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_11.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

qldb_ledgers := fugue.resources("aws_qldb_ledger")

iam_roles := fugue.resources("aws_iam_role")

iam_policies := fugue.resources("aws_iam_policy")

iam_role_policy_attachments := fugue.resources("aws_iam_role_policy_attachment")

has_iam_role(ledger) {
	count(iam_roles) > 0
}

has_iam_policy(ledger) {
	count(iam_policies) > 0
}

has_iam_role_policy_attachment(ledger) {
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
	ledger := qldb_ledgers[_]
	has_iam_role(ledger)
	has_iam_policy(ledger)
	has_iam_role_policy_attachment(ledger)
	policy := iam_policies[_]
	not is_full_admin_policy(policy)
	p = fugue.allow_resource(ledger)
}

policy[p] {
	ledger := qldb_ledgers[_]
	not has_iam_role(ledger)
	msg := sprintf("QLDB ledger '%s' does not have an associated IAM role", [ledger.name])
	p = fugue.deny_resource_with_message(ledger, msg)
}

policy[p] {
	ledger := qldb_ledgers[_]
	not has_iam_policy(ledger)
	msg := sprintf("QLDB ledger '%s' does not have an associated IAM policy", [ledger.name])
	p = fugue.deny_resource_with_message(ledger, msg)
}

policy[p] {
	ledger := qldb_ledgers[_]
	not has_iam_role_policy_attachment(ledger)
	msg := sprintf("QLDB ledger '%s' does not have an IAM role policy attachment", [ledger.name])
	p = fugue.deny_resource_with_message(ledger, msg)
}

policy[p] {
	ledger := qldb_ledgers[_]
	has_iam_policy(ledger)
	policy := iam_policies[_]
	is_full_admin_policy(policy)
	msg := sprintf("QLDB ledger '%s' has an IAM policy with full admin access", [ledger.name])
	p = fugue.deny_resource_with_message(ledger, msg)
}
