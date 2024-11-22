package rules.secretsmanager_rotation_period

import data.fugue

__rego__metadoc__ := {
	"id": "SecretsManager.4",
	"title": "Secrets Manager secrets should be rotated within a specified number of days",
	"description": "Secrets Manager secrets must be rotated within specified timeframe to minimize unauthorized access and security risks.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_SecretsManager.4"]},"severity":"Medium","author":"Starchitect Agent"},
}

# Define resource type as MULTIPLE to handle multiple resources
resource_type := "MULTIPLE"

# Get all Secrets Manager secrets
secrets := fugue.resources("aws_secretsmanager_secret")

secret_rotation := fugue.resources("aws_secretsmanager_secret_rotation")

# Define the maximum acceptable number of days for rotation
max_rotation_days := 30

# Check if a secret rotation is compliant with the rotation timeframe
is_rotation_compliant(rotation) {
	rotation.rotation_rules[_].automatically_after_days <= max_rotation_days
}

# Check if a secret has an associated rotation configuration and that it's compliant
has_compliant_rotation(secret) {
	rotation := secret_rotation[_]
	rotation.secret_id == secret.id
	is_rotation_compliant(rotation)
}

# Allow secrets with compliant rotation configuration
policy[p] {
	secret := secrets[_]
	has_compliant_rotation(secret)
	p = fugue.allow_resource(secret)
}

# Deny secrets without compliant rotation configuration
policy[p] {
	secret := secrets[_]
	not has_compliant_rotation(secret)
	p = fugue.deny_resource_with_message(
		secret,
		sprintf("Secrets Manager secret %s must have automatic rotation enabled with an interval within %d days.", [secret.name, max_rotation_days]),
	)
}
