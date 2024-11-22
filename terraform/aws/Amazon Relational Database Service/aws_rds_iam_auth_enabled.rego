package rules.rds_iam_auth_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "RDS.10",
	"title": "IAM authentication should be configured for RDS instances",
	"description": "RDS instances must have IAM database authentication enabled for secure, token-based access instead of passwords.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_RDS.10"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all RDS instances
rds_instances = fugue.resources("aws_db_instance")

# List of supported engines for IAM authentication
supported_engines = [
	"mysql",
	"postgres",
	"aurora",
	"aurora-mysql",
	"aurora-postgresql",
	"mariadb",
]

# Check if engine is supported
is_supported_engine(instance) {
	instance.engine == supported_engines[_]
}

# Check if IAM authentication is enabled
is_iam_auth_enabled(instance) {
	instance.iam_database_authentication_enabled == true
}

# Allow if instance has IAM auth enabled and uses supported engine
policy[p] {
	instance := rds_instances[_]
	is_supported_engine(instance)
	is_iam_auth_enabled(instance)
	p = fugue.allow_resource(instance)
}

# Deny if instance doesn't have IAM auth enabled but uses supported engine
policy[p] {
	instance := rds_instances[_]
	is_supported_engine(instance)
	not is_iam_auth_enabled(instance)
	p = fugue.deny_resource_with_message(instance, "RDS instance must have IAM database authentication enabled for secure access")
}
