package rules.gcp_sql_postgres_log_statement

import data.fugue

__rego__metadoc__ := {
	"id": "6.2.4",
	"title": "Ensure 'Log_statement' Database Flag for Cloud SQL PostgreSQL Instance Is Set Appropriately",
	"description": "Configure PostgreSQL log_statement flag to 'ddl' for appropriate SQL statement logging in Cloud SQL instances for security auditing.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.4"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL instances
postgres_instances = fugue.resources("google_sql_database_instance")

# Helper to check if instance is PostgreSQL
is_postgres(instance) {
	instance.database_version
	startswith(instance.database_version, "POSTGRES")
}

# Helper to check if log_statement flag is set appropriately
has_valid_log_statement(instance) {
	flag := instance.settings[_].database_flags[_]
	flag.name == "log_statement"
	flag.value == "ddl"
}

# Allow PostgreSQL instances with appropriate log_statement setting
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	has_valid_log_statement(instance)
	p = fugue.allow_resource(instance)
}

# Deny PostgreSQL instances with missing or incorrect log_statement setting
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	not has_valid_log_statement(instance)
	p = fugue.deny_resource_with_message(instance, "PostgreSQL instance must have log_statement database flag set to 'ddl'")
}
