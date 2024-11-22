package rules.kms_keys_not_public

import data.fugue

__rego__metadoc__ := {
	"id": "KMS.5",
	"title": "KMS keys should not be publicly accessible",
	"description": "This control checks if KMS keys have policies that allow public access. KMS keys should follow the principle of least privilege and restrict access to authorized principals only.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_KMS.5"]},"severity":"Critical","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

kms_keys = fugue.resources("aws_kms_key")

# Helper function to check if policy allows public access
has_public_access(policy_doc) {
	statement := policy_doc.Statement[_]
	statement.Effect == "Allow"
	principal := statement.Principal
	principal.AWS == "*"
}

# Check if key policy is publicly accessible
is_public(key) {
	policy_doc := json.unmarshal(key.policy)
	has_public_access(policy_doc)
}

policy[p] {
	key := kms_keys[_]
	not is_public(key)
	p = fugue.allow_resource(key)
}

policy[p] {
	key := kms_keys[_]
	is_public(key)
	p = fugue.deny_resource_with_message(key, "KMS key policy allows public access which violates security best practices")
}
