package rules.gcp_sql_server_user_options

import data.fugue

__rego__metadoc__ := {
	"id": "6.3.4",
	"title": "Ensure 'user options' database flag for Cloud SQL SQL Server instance is not configured",
	"description": "It is recommended that user options database flag for Cloud SQL SQL Server instance should not be configured to maintain secure default query processing settings.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.4"]}, "severity": "Medium", "author": "Starchitect Agent"},
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

# Check if instance is SQL Server and user_options flag is not configured
is_compliant(instance) {
	# Check if instance is SQL Server
	instance.database_version
	is_sql_server(instance)

	# Check database flags
	database_flags := instance.settings[_].database_flags
	flag := database_flags[_]
	not flag.name == "user options"
}

# Allow if instance is compliant
policy[p] {
	instance := sql_instances[_]
	is_compliant(instance)
	p = fugue.allow_resource(instance)
}

# Deny if user options flag is configured
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	database_flags := instance.settings[_].database_flags
	flag := database_flags[_]
	flag.name == "user options"
	p = fugue.deny_resource_with_message(
		instance,
		sprintf("SQL Server instance '%s' has 'user options' database flag configured which is not recommended", [instance.name]),
	)
}
