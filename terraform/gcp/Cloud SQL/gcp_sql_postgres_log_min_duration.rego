package rules.gcp_sql_postgres_log_min_duration

import data.fugue

__rego__metadoc__ := {
	"id": "6.2.7",
	"title": "Ensure PostgreSQL log_min_duration_statement flag is set to -1",
	"description": "The log_min_duration_statement flag for Cloud SQL PostgreSQL instances should be set to -1 to disable logging of SQL statement execution times for security purposes.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.7"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL instances
postgres_instances = fugue.resources("google_sql_database_instance")

# Helper to check if instance is PostgreSQL
is_postgres(instance) {
	startswith(instance.database_version, "POSTGRES")
}

# Helper to check if log_min_duration_statement is properly set
is_properly_configured(instance) {
	flags := instance.settings[0].database_flags
	flag := flags[_]
	flag.name == "log_min_duration_statement"
	flag.value == "-1"
}

# Allow if instance is properly configured
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	is_properly_configured(instance)
	p = fugue.allow_resource(instance)
}

# Deny if instance is not properly configured
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	not is_properly_configured(instance)
	p = fugue.deny_resource_with_message(
		instance,
		"PostgreSQL instance must have log_min_duration_statement flag set to -1",
	)
}
