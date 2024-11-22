package rules.gcp_sql_remote_access

import data.fugue

__rego__metadoc__ := {
	"id": "6.3.5",
	"title": "Ensure 'remote access' database flag for Cloud SQL SQL Server instance is set to 'off'",
	"description": "It is recommended to set remote access database flag for Cloud SQL SQL Server instance to off.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.5"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all SQL instances
sql_instances = fugue.resources("google_sql_database_instance")

sql_server_versions = {
	# SQL Server 2022 versions
	"SQLSERVER_2022_STANDARD",
	"SQLSERVER_2022_ENTERPRISE",
	"SQLSERVER_2022_EXPRESS",
	"SQLSERVER_2022_WEB",
	# SQL Server 2019 versions (default)
	"SQLSERVER_2019_STANDARD",
	"SQLSERVER_2019_ENTERPRISE",
	"SQLSERVER_2019_EXPRESS",
	"SQLSERVER_2019_WEB",
	# SQL Server 2017 versions
	"SQLSERVER_2017_STANDARD",
	"SQLSERVER_2017_ENTERPRISE",
	"SQLSERVER_2017_EXPRESS",
	"SQLSERVER_2017_WEB",
}

# Check if the instance is a SQL Server instance
is_sql_server(instance) {
	sql_server_versions[instance.database_version]
}

# Check if database flags are properly configured
has_remote_access_disabled(instance) {
	flags := instance.settings[_].database_flags[_]
	flags.name == "remote access"
	flags.value == "off"
}

# Allow if remote access is disabled
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	has_remote_access_disabled(instance)
	p = fugue.allow_resource(instance)
}

# Deny if remote access is not disabled
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	not has_remote_access_disabled(instance)
	p = fugue.deny_resource_with_message(
		instance,
		sprintf("SQL Server instance '%s' must have 'remote access' database flag set to 'off'", [instance.name]),
	)
}
