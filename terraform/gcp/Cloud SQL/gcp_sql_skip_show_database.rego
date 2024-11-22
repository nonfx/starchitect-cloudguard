package rules.gcp_sql_skip_show_database

import data.fugue

__rego__metadoc__ := {
	"id": "6.1.2",
	"title": "Ensure 'Skip_show_database' Database Flag for Cloud SQL MySQL Instance Is Set to 'On'",
	"description": "It is recommended to set skip_show_database database flag for Cloud SQL MySQL instance to on to prevent unauthorized users from viewing databases using SHOW DATABASES statement.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.1.2"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Cloud SQL instances
sql_instances = fugue.resources("google_sql_database_instance")

# Helper to check if instance is MySQL
is_mysql(instance) {
	instance.database_version
	startswith(instance.database_version, "MYSQL")
}

# Helper to check if skip_show_database flag is set to on
has_skip_show_database_on(instance) {
	flag := instance.settings[_].database_flags[_]
	flag.name == "skip_show_database"
	flag.value == "on"
}

# Allow MySQL instances with skip_show_database flag set to on
policy[p] {
	instance := sql_instances[_]
	is_mysql(instance)
	has_skip_show_database_on(instance)
	p = fugue.allow_resource(instance)
}

# Deny MySQL instances without skip_show_database flag set to on
policy[p] {
	instance := sql_instances[_]
	is_mysql(instance)
	not has_skip_show_database_on(instance)
	p = fugue.deny_resource_with_message(
		instance,
		"Cloud SQL MySQL instance must have skip_show_database flag set to 'on'",
	)
}
