package rules.gcp_sql_postgres_log_error_verbosity

import data.fugue

__rego__metadoc__ := {
	"id": "6.2.1",
	"title": "Ensure PostgreSQL log_error_verbosity flag is set appropriately",
	"description": "Ensure PostgreSQL log_error_verbosity flag is set to 'DEFAULT' or stricter for proper error message logging in Cloud SQL instances.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.1"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL instances
postgres_instances = fugue.resources("google_sql_database_instance")

# Helper to check if instance is PostgreSQL
is_postgres(instance) {
	startswith(instance.database_version, "POSTGRES")
}

# Helper to check if verbosity level is appropriate
has_appropriate_verbosity(instance) {
	flags := instance.settings[0].database_flags
	flag := flags[_]
	flag.name == "log_error_verbosity"
	flag.value == "DEFAULT"
}

# Allow PostgreSQL instances with appropriate verbosity setting
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	has_appropriate_verbosity(instance)
	p = fugue.allow_resource(instance)
}

# Deny PostgreSQL instances with missing or inappropriate verbosity setting
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	not has_appropriate_verbosity(instance)
	p = fugue.deny_resource_with_message(instance, "PostgreSQL instance must have log_error_verbosity flag set to 'DEFAULT'")
}
