package rules.athena_workgroup_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "ATHENA_4",
	"title": "Athena workgroups should have logging enabled",
	"description": "This control checks whether Amazon Athena workgroups have CloudWatch metrics logging enabled. Logging helps track query metrics for security monitoring and compliance purposes.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_Athena.4"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all Athena workgroup resources
athena_workgroups = fugue.resources("aws_athena_workgroup")

# Helper function to check if metrics logging is enabled
is_logging_enabled(workgroup) {
	workgroup.configuration[_].publish_cloudwatch_metrics_enabled == true
}

# Allow policy for compliant workgroups
policy[p] {
	workgroup := athena_workgroups[_]
	is_logging_enabled(workgroup)
	p = fugue.allow_resource(workgroup)
}

# Deny policy for non-compliant workgroups
policy[p] {
	workgroup := athena_workgroups[_]
	not is_logging_enabled(workgroup)
	p = fugue.deny_resource_with_message(workgroup, "Athena workgroup does not have CloudWatch metrics logging enabled")
}
