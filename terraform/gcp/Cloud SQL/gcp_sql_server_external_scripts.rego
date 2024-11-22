package rules.gcp_sql_server_external_scripts

import data.fugue

__rego__metadoc__ := {
	"id": "6.3.1",
	"title": "Ensure 'external scripts enabled' database flag for Cloud SQL SQL Server instance is set to 'off'",
	"description": "It is recommended to set external scripts enabled database flag for Cloud SQL SQL Server instance to off",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.1"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all SQL Server instances
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

# Check if instance is SQL Server and external scripts are disabled
is_compliant(instance) {
	# Check if it's a SQL Server instance
	instance.database_version
	is_sql_server(instance)

	# Check database flags
	flags := instance.settings[_].database_flags
	flag := flags[_]
	flag.name == "external scripts enabled"
	flag.value == "off"
}

# Allow if instance is compliant
policy[p] {
	instance := sql_instances[_]
	is_compliant(instance)
	p = fugue.allow_resource(instance)
}

# Deny if SQL Server instance has external scripts enabled or flag is missing
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	not is_compliant(instance)
	p = fugue.deny_resource_with_message(
		instance,
		sprintf("SQL Server instance '%s' should have 'external scripts enabled' flag set to 'off'", [instance.name]),
	)
}
