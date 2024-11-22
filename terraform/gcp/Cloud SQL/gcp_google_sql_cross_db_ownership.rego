package rules.google_sql_cross_db_ownership

import data.fugue

__rego__metadoc__ := {
	"id": "6.3.2",
	"title": "Ensure that the 'cross db ownership chaining' database flag for Cloud SQL SQL Server instance is set to 'off' (Automated)",
	"description": "It is recommended to set cross db ownership chaining database flag for Cloud SQL SQL Server instance to off. This flag is deprecated for all SQL Server versions in CGP. Going forward, you can't set its value to on. However, if you have this flag enabled, we strongly recommend that you either remove the flag from your database or set it to off. For cross-database access, use the Microsoft tutorial for signing stored procedures with a certificate..",
	"custom": {"severity": "High", "controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.2"]}, "author": "Starchitect Agent"},
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

# Check if database flags are properly configured
is_compliant(instance) {
	# Check if it's a SQL Server instance
	is_sql_server(instance)

	# Check database flags
	flag := instance.settings[_].database_flags[_]
	flag.name == "cross db ownership chaining"
	flag.value == "off"
}

# Allow if instance is compliant
policy[p] {
	instance := sql_instances[_]
	is_compliant(instance)
	p = fugue.allow_resource(instance)
}

# Deny if cross db ownership chaining is not set to off
policy[p] {
	instance := sql_instances[_]
	instance.database_version == "SQLSERVER_2017_STANDARD"
	not is_compliant(instance)
	p = fugue.deny_resource_with_message(
		instance,
		"Cross db ownership chaining must be set to 'off' for SQL Server instances",
	)
}
