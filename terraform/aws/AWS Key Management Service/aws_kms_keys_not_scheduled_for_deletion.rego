package rules.kms_keys_not_scheduled_for_deletion

import data.fugue

__rego__metadoc__ := {
	"id": "KMS.3",
	"title": "AWS KMS keys should not be scheduled for deletion",
	"description": "This control checks if any KMS keys are scheduled for deletion. KMS keys and their encrypted data cannot be recovered once deleted, potentially causing permanent data loss.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_KMS.3"]}, "severity": "Critical", "reviewer": "ssghait.007@gmail.com"},
}

# Define resource type
resource_type := "MULTIPLE"

# Get all KMS key resources
kms_keys = fugue.resources("aws_kms_key")

# Helper function to check if key is scheduled for deletion
is_scheduled_for_deletion(key) {
	key.deletion_window_in_days != null
}

# Allow KMS keys that are not scheduled for deletion
policy[p] {
	key := kms_keys[_]
	not is_scheduled_for_deletion(key)
	p = fugue.allow_resource(key)
}

# Deny KMS keys that are scheduled for deletion
policy[p] {
	key := kms_keys[_]
	is_scheduled_for_deletion(key)
	p = fugue.deny_resource_with_message(key, "KMS key is scheduled for deletion which could result in permanent data loss")
}
