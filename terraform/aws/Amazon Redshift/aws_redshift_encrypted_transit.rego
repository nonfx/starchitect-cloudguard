package rules.redshift_encrypted_transit

import data.fugue

__rego__metadoc__ := {
	"id": "Redshift.2",
	"title": "Redshift clusters must have encrypted transit enabled",
	"description": "This rule ensures that Amazon Redshift clusters require SSL/TLS for encrypted connections.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Redshift.2"]},
		"severity": "HIGH",
	},
}

resource_type := "MULTIPLE"

redshift_parameter_group = fugue.resources("aws_redshift_parameter_group")

# Helper function to check if SSL is required in parameter group
is_ssl_required(group) {
	param := group.parameter[_]
	param.name == "require_ssl"
	param.value == "true"
}

# Allow rule for compliant parameter groups
policy[p] {
	group := redshift_parameter_group[_]
	is_ssl_required(group)
	p = fugue.allow_resource(group)
}

# Deny rule for non-compliant parameter groups
policy[p] {
	group := redshift_parameter_group[_]
	not is_ssl_required(group)
	p = fugue.deny_resource_with_message(
		group,
		"Redshift parameter group must have require_ssl parameter set to true",
	)
}
