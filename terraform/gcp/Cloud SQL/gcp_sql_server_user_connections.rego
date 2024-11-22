package rules.gcp_sql_server_user_connections

import data.fugue
import future.keywords.contains
import future.keywords.if
import future.keywords.in

__rego__metadoc__ := {
	"id": "6.3.3",
	"title": "Ensure 'user Connections' Database Flag for Cloud Sql Sql Server Instance Is Set to a Non-limiting Value",
	"description": "It is recommended to check the user connections for a Cloud SQL SQL Server instance to ensure that it is not artificially limiting connections.",
	"custom": {"controls":{"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0":["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.3"]},"severity":"Medium","author":"Starchitect Agent"},
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

# Check if instance has unlimited user connections
has_unlimited_connections(instance) {
	flag := instance.settings[_].database_flags[_]
	flag.name == "user connections"
	to_number(flag.value) == 0
}

# Check if instance has limited user connections
has_limited_connections(instance) {
	flag := instance.settings[_].database_flags[_]
	flag.name == "user connections"
	to_number(flag.value) > 0
}

# Allow if SQL Server instance has unlimited connections
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	has_unlimited_connections(instance)
	p = fugue.allow_resource(instance)
}

# Deny if SQL Server instance has limited connections
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	has_limited_connections(instance)
	p = fugue.deny_resource_with_message(
		instance,
		sprintf("Cloud SQL SQL Server instance '%s' has limited user connections. Set 'user connections' flag to 0 for unlimited connections.", [instance.name]),
	)
}

# Deny if SQL Server instance is missing user connections flag
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	not has_unlimited_connections(instance)
	not has_limited_connections(instance)
	p = fugue.deny_resource_with_message(
		instance,
		sprintf("Cloud SQL SQL Server instance '%s' is missing the 'user connections' flag configuration.", [instance.name]),
	)
}
