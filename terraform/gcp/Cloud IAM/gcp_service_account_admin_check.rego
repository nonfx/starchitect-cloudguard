package rules.gcp_service_account_admin_check

import data.fugue

__rego__metadoc__ := {
	"id": "1.5",
	"title": "Service accounts should not have admin privileges",
	"description": "Service accounts should not be granted administrative privileges to maintain security and prevent unauthorized access to Google Cloud resources.",
	"custom": {
		"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_1.5"]},
		"severity": "Critical",
	},
}

resource_type := "MULTIPLE"

# Get all IAM policy bindings and members
iam_bindings = fugue.resources("google_project_iam_binding")

iam_members = fugue.resources("google_project_iam_member")

# Check if role is administrative
is_admin_role(role) {
	admin_roles = [
		"roles/editor",
		"roles/owner",
		"roles/admin",
	]
	role == admin_roles[_]
}

is_admin_role(role) {
	contains(lower(role), "admin")
}

# Check if member is a service account
is_service_account(member) {
	startswith(member, "serviceAccount:")
}

# Evaluate IAM bindings
policy[p] {
	binding := iam_bindings[_]
	member := binding.members[_]
	is_service_account(member)
	not is_admin_role(binding.role)
	p = fugue.allow_resource(binding)
}

policy[p] {
	binding := iam_bindings[_]
	member := binding.members[_]
	is_service_account(member)
	is_admin_role(binding.role)
	p = fugue.deny_resource_with_message(
		binding,
		sprintf("Service account %s should not have administrative role %s", [member, binding.role]),
	)
}

# Evaluate IAM members
policy[p] {
	member := iam_members[_]
	is_service_account(member.member)
	not is_admin_role(member.role)
	p = fugue.allow_resource(member)
}

policy[p] {
	member := iam_members[_]
	is_service_account(member.member)
	is_admin_role(member.role)
	p = fugue.deny_resource_with_message(
		member,
		sprintf("Service account %s should not have administrative role %s", [member.member, member.role]),
	)
}
