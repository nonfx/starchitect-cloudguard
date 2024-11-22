package rules.macie_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "Macie.1",
	"title": "Amazon Macie should be enabled",
	"description": "This control checks if Amazon Macie is enabled for the AWS account. Macie uses machine learning and pattern matching to discover and protect sensitive data in S3 buckets.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_Macie.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Macie account configurations
macie_sessions = fugue.resources("aws_macie2_account")

# Function to check if Macie is enabled
is_macie_enabled(session) {
	session.status == "ENABLED"
}

# Allow if Macie is enabled
policy[p] {
	session := macie_sessions[_]
	is_macie_enabled(session)
	p = fugue.allow_resource(session)
}

# Deny if Macie is disabled
policy[p] {
	session := macie_sessions[_]
	not is_macie_enabled(session)
	p = fugue.deny_resource_with_message(session, "Amazon Macie is not enabled for this account")
}

# Report missing Macie configuration
policy[p] {
	count(macie_sessions) == 0
	p = fugue.missing_resource_with_message("aws_macie2_account", "Amazon Macie is not configured for this account")
}
