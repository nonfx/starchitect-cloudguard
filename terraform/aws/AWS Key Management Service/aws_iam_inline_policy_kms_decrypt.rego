package rules.iam_inline_policy_kms_decrypt

import data.fugue

__rego__metadoc__ := {
	"id": "KMS.2",
	"title": "IAM principals should not have IAM inline policies that allow decryption actions on all KMS keys",
	"description": "This control checks if IAM inline policies allow decryption actions on all KMS keys. Following least privilege principle, policies should restrict KMS actions to specific keys.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_KMS.2"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

# Get all IAM resources that can have inline policies
iam_users = fugue.resources("aws_iam_user_policy")

iam_roles = fugue.resources("aws_iam_role_policy")

iam_groups = fugue.resources("aws_iam_group_policy")

# List of KMS decrypt actions to check
decrypt_actions = ["kms:Decrypt", "kms:ReEncryptFrom"]

# Helper to check if policy allows decrypt actions on all keys
has_decrypt_all_keys(policy_doc) {
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	action := statement.Action[_]
	action == decrypt_actions[_]
	resource := statement.Resource
	resource == "*"
}

# Check inline policies for users
policy[p] {
	policy := iam_users[_]
	policy_doc := json.unmarshal(policy.policy)
	has_decrypt_all_keys(policy_doc)
	p = fugue.deny_resource_with_message(policy, "IAM user inline policy allows KMS decrypt actions on all keys")
}

# Check inline policies for roles
policy[p] {
	policy := iam_roles[_]
	policy_doc := json.unmarshal(policy.policy)
	has_decrypt_all_keys(policy_doc)
	p = fugue.deny_resource_with_message(policy, "IAM role inline policy allows KMS decrypt actions on all keys")
}

# Check inline policies for groups
policy[p] {
	policy := iam_groups[_]
	policy_doc := json.unmarshal(policy.policy)
	has_decrypt_all_keys(policy_doc)
	p = fugue.deny_resource_with_message(policy, "IAM group inline policy allows KMS decrypt actions on all keys")
}

# Allow policies that don't have broad decrypt permissions
policy[p] {
	policy := iam_users[_]
	policy_doc := json.unmarshal(policy.policy)
	not has_decrypt_all_keys(policy_doc)
	p = fugue.allow_resource(policy)
}

policy[p] {
	policy := iam_roles[_]
	policy_doc := json.unmarshal(policy.policy)
	not has_decrypt_all_keys(policy_doc)
	p = fugue.allow_resource(policy)
}

policy[p] {
	policy := iam_groups[_]
	policy_doc := json.unmarshal(policy.policy)
	not has_decrypt_all_keys(policy_doc)
	p = fugue.allow_resource(policy)
}
