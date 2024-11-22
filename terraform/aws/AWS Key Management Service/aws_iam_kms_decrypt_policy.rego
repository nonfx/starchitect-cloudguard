package rules.iam_kms_decrypt_policy

import data.fugue

__rego__metadoc__ := {
	"id": "KMS.1",
	"title": "IAM customer managed policies should not allow decryption actions on all KMS keys",
	"description": "This control checks if IAM customer managed policies allow decryption actions (kms:Decrypt or kms:ReEncryptFrom) on all KMS keys. Following least privilege principles, policies should restrict these actions to specific keys.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_KMS.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

iam_policies = fugue.resources("aws_iam_policy")

# List of KMS decryption actions that should be restricted
decryption_actions = ["kms:Decrypt", "kms:ReEncryptFrom"]

# Check if action is a KMS decryption action
is_decryption_action(action) {
	decryption_actions[_] == action
}

# Check if resource allows all KMS keys
is_all_kms_resources(resource) {
	resource == "*"
}

is_all_kms_resources(resource) {
	startswith(resource, "arn:aws:kms:")
	endswith(resource, "*")
}

# Check if policy allows decryption on all KMS keys
has_unrestricted_decrypt(policy) {
	policy_doc := json.unmarshal(policy.policy)
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	action := statement.Action[_]
	is_decryption_action(action)
	resource := statement.Resource[_]
	is_all_kms_resources(resource)
}

policy[p] {
	policy := iam_policies[_]
	not has_unrestricted_decrypt(policy)
	p = fugue.allow_resource(policy)
}

policy[p] {
	policy := iam_policies[_]
	has_unrestricted_decrypt(policy)
	p = fugue.deny_resource_with_message(policy, "IAM policy allows KMS decryption actions on all keys. Restrict to specific key ARNs.")
}
