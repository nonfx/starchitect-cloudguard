package rules.gcp_sql_local_infile_off

import data.fugue

__rego__metadoc__ := {
	"id": "6.1.3",
	"title": "Ensure That the 'Local_infile' Database Flag for Cloud SQL MySQL Instance Is Set to 'Off'",
	"description": "It is recommended to set the local_infile database flag for a Cloud SQL MySQL instance to off to prevent unauthorized local data loading.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.1.3"]}, "severity": "High", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Cloud SQL instances
sql_instances = fugue.resources("google_sql_database_instance")

# Helper to check if instance is MySQL
is_mysql(instance) {
	instance.database_version
	startswith(instance.database_version, "MYSQL")
}

# Helper to check if local_infile is disabled
is_local_infile_disabled(instance) {
	flag := instance.settings[_].database_flags[_]
	flag.name == "local_infile"
	flag.value == "off"
}

# Allow if MySQL instance has local_infile disabled
policy[p] {
	instance := sql_instances[_]
	is_mysql(instance)
	is_local_infile_disabled(instance)
	p = fugue.allow_resource(instance)
}

# Deny if MySQL instance has local_infile enabled or not set
policy[p] {
	instance := sql_instances[_]
	is_mysql(instance)
	not is_local_infile_disabled(instance)
	p = fugue.deny_resource_with_message(instance, "Cloud SQL MySQL instance must have local_infile flag set to 'off'")
}
