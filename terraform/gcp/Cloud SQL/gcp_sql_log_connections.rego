package rules.gcp_sql_log_connections

import data.fugue

__rego__metadoc__ := {
	"id": "6.2.2",
	"title": "Ensure That the 'Log_connections' Database Flag for Cloud SQL PostgreSQL Instance Is Set to 'On'",
	"description": "Enabling the log_connections setting causes each attempted connection to the server to be logged, along with successful completion of client authentication.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

# Define resource type
resource_type := "MULTIPLE"

# Get all SQL instances
sql_instances = fugue.resources("google_sql_database_instance")

# Check if instance is PostgreSQL
is_postgres(instance) {
	startswith(instance.database_version, "POSTGRES")
}

# Validate log_connections flag
has_log_connections_on(instance) {
	flag := instance.settings[_].database_flags[_]
	flag.name == "log_connections"
	flag.value == "on"
}

# Allow if compliant
policy[p] {
	instance := sql_instances[_]
	is_postgres(instance)
	has_log_connections_on(instance)
	p = fugue.allow_resource(instance)
}

# Deny if non-compliant
policy[p] {
	instance := sql_instances[_]
	is_postgres(instance)
	not has_log_connections_on(instance)
	p = fugue.deny_resource_with_message(
		instance,
		"Cloud SQL PostgreSQL instance must have log_connections flag set to 'on'",
	)
}
