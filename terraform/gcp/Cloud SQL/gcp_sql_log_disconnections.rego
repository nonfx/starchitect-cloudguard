package rules.gcp_sql_log_disconnections

import data.fugue

__rego__metadoc__ := {
	"id": "6.2.3",
	"title": "Ensure log_disconnections database flag is set to 'on'",
	"description": "Cloud SQL PostgreSQL instances should have log_disconnections flag enabled to track session endings and durations.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Cloud SQL instances
sql_instances = fugue.resources("google_sql_database_instance")

# Helper to check if instance is PostgreSQL
is_postgres(db) {
	contains(lower(db.database_version), "postgres")
}

# Helper to check if log_disconnections is enabled
has_log_disconnections_enabled(db) {
	flag := db.settings[_].database_flags[_]
	flag.name == "log_disconnections"
	flag.value == "on"
}

# Evaluate PostgreSQL instances
policy[p] {
	resource := sql_instances[_]
	is_postgres(resource)
	not has_log_disconnections_enabled(resource)
	p = fugue.deny_resource_with_message(
		resource,
		sprintf("PostgreSQL instance '%v' must have log_disconnections flag set to 'on'", [resource.name]),
	)
}

# Allow compliant instances
policy[p] {
	resource := sql_instances[_]
	is_postgres(resource)
	has_log_disconnections_enabled(resource)
	p = fugue.allow_resource(resource)
}
