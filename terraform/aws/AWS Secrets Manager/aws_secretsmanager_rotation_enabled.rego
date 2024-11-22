package rules.secretsmanager_rotation_enabled

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "SecretsManager.1",
	"title": "Secrets Manager secrets should have automatic rotation enabled",
	"description": "This control checks whether AWS Secrets Manager secrets are configured with automatic rotation. Automatic rotation helps improve security by regularly replacing long-term secrets with new ones.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_SecretsManager.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

secrets = fugue.resources("aws_secretsmanager_secret")

secret_rotations = fugue.resources("aws_secretsmanager_secret_rotation")

# Helper function to get rotation configuration for a secret
get_rotation_config(secret_id) = config {
	some rotation in secret_rotations
	rotation.secret_id == secret_id
	config = rotation
}

# Check if rotation is properly configured
is_valid_rotation(secret) {
	rotation := get_rotation_config(secret.id)
	rotation != null
	rotation.rotation_lambda_arn != null
	rotation.rotation_lambda_arn != ""
	rotation.rotation_rules[_].automatically_after_days > 0
}

# Allow secrets with valid rotation configuration
policy[p] {
	secret := secrets[_]
	is_valid_rotation(secret)
	p = fugue.allow_resource(secret)
}

# Deny secrets without valid rotation configuration
policy[p] {
	secret := secrets[_]
	not is_valid_rotation(secret)
	p = fugue.deny_resource_with_message(secret, "Secrets Manager secret must have automatic rotation enabled with a valid rotation Lambda function and rotation period")
}
