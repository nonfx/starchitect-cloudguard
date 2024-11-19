package rules.rds_enhanced_monitoring_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.6",
	"title": "Enhanced monitoring should be configured for RDS DB instances",
	"description": "This control checks if enhanced monitoring is enabled for RDS DB instances with appropriate monitoring interval and role configuration.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.6"]}, "severity": "Low", "author": "llmagent"},
}

resource_type := "MULTIPLE"

rds_instances = fugue.resources("aws_db_instance")

# Valid monitoring intervals in seconds
valid_intervals = {1, 5, 10, 15, 30, 60}

# Check if monitoring interval is valid
is_valid_interval(instance) {
	valid_intervals[instance.monitoring_interval]
}

# Check if monitoring role ARN is configured
has_monitoring_role(instance) {
	instance.monitoring_role_arn != null
	instance.monitoring_role_arn != ""
}

# Allow if enhanced monitoring is properly configured
policy[p] {
	instance := rds_instances[_]
	is_valid_interval(instance)
	has_monitoring_role(instance)
	p = fugue.allow_resource(instance)
}

# Deny if monitoring interval is invalid
policy[p] {
	instance := rds_instances[_]
	not is_valid_interval(instance)
	p = fugue.deny_resource_with_message(
		instance,
		sprintf(
			"RDS instance has invalid monitoring interval %d. Must be one of: 1, 5, 10, 15, 30, or 60 seconds",
			[instance.monitoring_interval],
		),
	)
}

# Deny if monitoring role is missing
policy[p] {
	instance := rds_instances[_]
	not has_monitoring_role(instance)
	p = fugue.deny_resource_with_message(
		instance,
		"RDS instance must have a monitoring role ARN configured for enhanced monitoring",
	)
}
