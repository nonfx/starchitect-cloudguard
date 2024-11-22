package rules.dms_endpoints_ssl_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "DMS.9",
	"title": "DMS endpoints should use SSL",
	"description": "DMS endpoints must use SSL connections to encrypt data during migration, ensuring secure data transfer between source and target databases.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_DMS.9"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

dms_endpoints = fugue.resources("aws_dms_endpoint")

# Helper to check if SSL is properly configured
is_ssl_enabled(endpoint) {
	endpoint.ssl_mode != "none"
	endpoint.ssl_mode != "disable"
}

# Policy rule for allowing endpoints with SSL enabled
policy[p] {
	endpoint := dms_endpoints[_]
	is_ssl_enabled(endpoint)
	p = fugue.allow_resource(endpoint)
}

# Policy rule for denying endpoints without SSL
policy[p] {
	endpoint := dms_endpoints[_]
	not is_ssl_enabled(endpoint)
	p = fugue.deny_resource_with_message(
		endpoint,
		"DMS endpoint must use SSL for secure data transfer",
	)
}
