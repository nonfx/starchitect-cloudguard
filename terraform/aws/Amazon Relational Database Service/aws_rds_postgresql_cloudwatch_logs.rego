package rules.rds_postgresql_cloudwatch_logs

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.36",
	"title": "RDS for PostgreSQL DB instances should publish logs to CloudWatch Logs",
	"description": "This control checks whether RDS PostgreSQL DB instances are configured to publish logs to CloudWatch Logs.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.36"]}, "severity": "Medium", "author": "llmagent"},
}

resource_type := "MULTIPLE"

# Query for all db instances
aws_db_instance = fugue.resources("aws_db_instance")

# Check if instance is PostgreSQL and has required logs enabled
is_compliant(resource) {
	# Check if it's a PostgreSQL instance
	resource.engine == "postgres"

	# Check if CloudWatch log exports are configured
	log_type := resource.enabled_cloudwatch_logs_exports[_]
	log_type == "postgresql"
}

# Allow compliant PostgreSQL instances
policy[r] {
	resource := aws_db_instance[_]
	is_compliant(resource)
	r = fugue.allow_resource(resource)
}

# Deny non-compliant PostgreSQL instances
policy[r] {
	resource := aws_db_instance[_]
	resource.engine == "postgres"
	not is_compliant(resource)
	r = fugue.deny_resource_with_message(
		resource,
		"RDS PostgreSQL instance must be configured to publish postgresql logs to CloudWatch Logs",
	)
}
