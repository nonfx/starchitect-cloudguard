package rules.gcp_sql_postgres_log_min_messages

import data.fugue
import future.keywords.in

__rego__metadoc__ := {
	"id": "6.2.5",
	"title": "Ensure PostgreSQL log_min_messages flag is set appropriately",
	"description": "Ensure that the 'Log_min_messages' Flag for a Cloud SQL PostgreSQL Instance is set at minimum to 'Warning' or higher severity level.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.5"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL instances
postgres_instances = fugue.resources("google_sql_database_instance")

# Helper to check if instance is PostgreSQL
is_postgres(instance) {
	instance.database_version != ""
	startswith(lower(instance.database_version), "postgres")
}

# Helper to check minimum severity level
is_valid_severity(value) {
	valid_levels := {"WARNING", "ERROR", "LOG", "FATAL", "PANIC"}
	upper(value) in valid_levels
}

# Helper to check if log_min_messages is set appropriately
has_valid_log_min_messages(instance) {
	flags := instance.settings[_].database_flags
	flag := flags[_]
	flag.name == "log_min_messages"
	is_valid_severity(flag.value)
}

# Allow PostgreSQL instances with appropriate log_min_messages setting
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	has_valid_log_min_messages(instance)
	p = fugue.allow_resource(instance)
}

# Deny PostgreSQL instances with inappropriate log_min_messages setting
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	not has_valid_log_min_messages(instance)
	p = fugue.deny_resource_with_message(
		instance,
		"PostgreSQL instance must have log_min_messages set to 'WARNING' or higher severity level",
	)
}
