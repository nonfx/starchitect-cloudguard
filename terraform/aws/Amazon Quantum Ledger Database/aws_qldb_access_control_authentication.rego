package rules.aws_qldb_access_control_authentication

import data.fugue

__rego__metadoc__ := {
	"id": "11.5",
	"title": "Ensure to Implement Access Control and Authentication",
	"description": "Utilize QLDB's built-in authentication and access control mechanisms. Define IAM policies to control which users or roles can perform specific actions on QLDB resources. Leverage IAM roles for cross-service access, securely integrating QLDB with other AWS services.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_11.5"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

qldb_ledgers := fugue.resources("aws_qldb_ledger")

iam_policies := fugue.resources("aws_iam_policy")

# Helper function to check if a policy document contains QLDB-specific permissions
has_qldb_permissions(policy_document) {
	statement := policy_document.Statement[_]
	statement.Effect == "Allow"
	startswith(statement.Action[_], "qldb:")
}

# Check if any IAM policy has QLDB-specific permissions
qldb_policy_exists {
	policy := iam_policies[_]
	policy_doc := json.unmarshal(policy.policy)
	has_qldb_permissions(policy_doc)
}

policy[p] {
	ledger := qldb_ledgers[_]
	ledger.permissions_mode == "STANDARD"
	qldb_policy_exists
	p := fugue.allow_resource(ledger)
}

policy[p] {
	ledger := qldb_ledgers[_]
	ledger.permissions_mode != "STANDARD"
	msg := sprintf("QLDB ledger '%s' does not have STANDARD permissions mode. Enable IAM-based authentication and access control.", [ledger.id])
	p := fugue.deny_resource_with_message(ledger, msg)
}

policy[p] {
	ledger := qldb_ledgers[_]
	ledger.permissions_mode == "STANDARD"
	not qldb_policy_exists
	msg := sprintf("QLDB ledger '%s' has STANDARD permissions mode, but no IAM policies with QLDB-specific permissions exist. Create appropriate IAM policies for access control.", [ledger.id])
	p := fugue.deny_resource_with_message(ledger, msg)
}
