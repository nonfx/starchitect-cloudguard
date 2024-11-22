package rules.gcp_cloudsql_pgaudit_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "6.2.8",
	"title": "Ensure cloudsql.enable_pgaudit database flag is enabled for PostgreSQL instances",
	"description": "PostgreSQL instances should have cloudsql.enable_pgaudit database flag enabled for comprehensive security logging and monitoring.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.2.8"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL instances
postgres_instances = fugue.resources("google_sql_database_instance")

postgres_versions = {
	"POSTGRES_17",
	"POSTGRES_16", # default
	"POSTGRES_15",
	"POSTGRES_14",
	"POSTGRES_13",
	"POSTGRES_12",
	"POSTGRES_11",
	"POSTGRES_10",
	"POSTGRES_9_6",
}

is_postgres(instance) {
	postgres_versions[instance.database_version]
}

# Check if instance is PostgreSQL and has pgaudit enabled
is_compliant(instance) {
	# Check if database is PostgreSQL
	instance.database_version
	is_postgres(instance)

	# Check database flags
	flags := instance.settings[_].database_flags
	flag := flags[_]
	flag.name == "cloudsql.enable_pgaudit"
	flag.value == "on"
}

# Allow compliant instances
policy[p] {
	instance := postgres_instances[_]
	is_compliant(instance)
	p = fugue.allow_resource(instance)
}

# Deny non-compliant instances
policy[p] {
	instance := postgres_instances[_]
	is_postgres(instance)
	not is_compliant(instance)
	p = fugue.deny_resource_with_message(
		instance,
		sprintf(
			"PostgreSQL instance '%s' does not have cloudsql.enable_pgaudit flag enabled",
			[instance.name],
		),
	)
}
