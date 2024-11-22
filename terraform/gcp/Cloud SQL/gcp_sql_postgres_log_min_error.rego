package rules.gcp_sql_postgres_log_min_error

import data.fugue

__rego__metadoc__ := {
	"id": "6.2.6",
	"title": "Ensure PostgreSQL log_min_error_statement flag is set to ERROR or stricter",
	"description": "This rule ensures that PostgreSQL instances have log_min_error_statement set to ERROR or stricter levels (FATAL, PANIC) for proper error message classification and logging.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.6"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL instances
postgres_instances = fugue.resources("google_sql_database_instance")

# Valid strict levels for log_min_error_statement
valid_levels = {"ERROR", "FATAL", "PANIC"}

# Helper to check if instance is PostgreSQL
is_postgres(instance) {
	startswith(instance.database_version, "POSTGRES")
}

# Helper to check if log_min_error_statement is set correctly
has_valid_error_level(instance) {
	flag := instance.settings[0].database_flags[_]
	flag.name == "log_min_error_statement"
	flag.value == valid_levels[_]
}

# Allow PostgreSQL instances with correct log_min_error_statement setting
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	has_valid_error_level(instance)
	p = fugue.allow_resource(instance)
}

# Deny PostgreSQL instances with incorrect or missing log_min_error_statement setting
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	not has_valid_error_level(instance)
	p = fugue.deny_resource_with_message(instance, "PostgreSQL instance must have log_min_error_statement set to ERROR or stricter (FATAL, PANIC)")
}
