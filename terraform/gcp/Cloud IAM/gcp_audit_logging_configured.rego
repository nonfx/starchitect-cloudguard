package rules.gcp_audit_logging_configured

import data.fugue

__rego__metadoc__ := {
	"id": "2.1",
	"title": "Ensure Cloud Audit Logging is configured properly",
	"description": "It is recommended that Cloud Audit Logging is configured to track all admin activities and read write access to user data.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_2.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all audit config resources
audit_configs = fugue.resources("google_project_iam_audit_config")

# Required audit log types
required_log_types = {
	"ADMIN_READ",
	"DATA_READ",
	"DATA_WRITE",
}

# Helper to check if all required log types are enabled
has_required_log_types(config) {
	# Create a set of configured log types
	configured_types := {x.log_type | x := config.audit_log_config[_]}

	# Check if all required types are present
	required_log_types & configured_types == required_log_types
}

# Allow if all required log types are configured
policy[p] {
	config := audit_configs[_]
	has_required_log_types(config)
	p = fugue.allow_resource(config)
}

# Deny if any required log type is missing
policy[p] {
	config := audit_configs[_]
	not has_required_log_types(config)
	missing := required_log_types - {x.log_type | x := config.audit_log_config[_]}
	p = fugue.deny_resource_with_message(
		config,
		sprintf(
			"Cloud Audit Logging is missing required log types: %v",
			[missing],
		),
	)
}
