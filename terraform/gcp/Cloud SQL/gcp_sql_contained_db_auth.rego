package rules.gcp_sql_contained_db_auth

import data.fugue

__rego__metadoc__ := {
	"id": "6.3.7",
	"title": "Ensure that the 'contained database authentication' database flag for Cloud SQL on the SQL Server instance is not set to 'on'",
	"description": "It is recommended not to set contained database authentication database flag for Cloud SQL on the SQL Server instance to on.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.7"]}, "severity": "Medium", "author": "Starchitect Agent"},
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

# Check if database flags contain contained database authentication set to on
has_contained_db_auth_on(instance) {
	flag := instance.settings[_].database_flags[_]
	flag.name == "contained database authentication"
	flag.value == "on"
}

# Deny if contained database authentication is enabled
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	has_contained_db_auth_on(instance)
	p = fugue.deny_resource_with_message(
		instance,
		sprintf("SQL Server instance '%s' has contained database authentication enabled", [instance.name]),
	)
}

# Allow if contained database authentication is not enabled
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	not has_contained_db_auth_on(instance)
	p = fugue.allow_resource(instance)
}
