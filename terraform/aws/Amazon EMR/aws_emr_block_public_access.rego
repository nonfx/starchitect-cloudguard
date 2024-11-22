package rules.emr_block_public_access

import data.fugue

__rego__metadoc__ := {
	"id": "EMR.2",
	"title": "Amazon EMR block public access setting should be enabled",
	"description": "This control checks if EMR block public access is enabled for the AWS account. The control fails if block public access is disabled or if ports other than 22 are allowed for inbound traffic.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EMR.2"]},"severity":"Critical","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all EMR block public access configurations
emr_block_access = fugue.resources("aws_emr_block_public_access_configuration")

# Helper to check if block public access is properly configured
is_properly_configured(config) {
	# Verify block_public_security_group_rules is enabled
	config.block_public_security_group_rules == true

	# Verify permitted rules only contain port 22
	rules := config.permitted_public_security_group_rule_range
	rule := rules[_]
	rule.min_range == 22
	rule.max_range == 22
}

# Allow if block public access is properly configured
policy[p] {
	config := emr_block_access[_]
	is_properly_configured(config)
	p = fugue.allow_resource(config)
}

# Deny if block public access is not properly configured
policy[p] {
	config := emr_block_access[_]
	not is_properly_configured(config)
	p = fugue.deny_resource_with_message(config, "EMR block public access must be enabled and only port 22 should be allowed for inbound traffic")
}

# Deny if no block public access configuration exists
policy[p] {
	count(emr_block_access) == 0
	p = fugue.missing_resource_with_message("aws_emr_block_public_access_configuration", "EMR block public access configuration is missing")
}
