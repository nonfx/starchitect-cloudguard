package rules.gcp_sql_trace_flag_3625

import data.fugue

__rego__metadoc__ := {
	"id": "6.3.6",
	"title": "Ensure '3625 (trace flag)' database flag for all Cloud SQL Server instances is set to 'on'",
	"description": "It is recommended to set 3625 (trace flag) database flag for Cloud SQL SQL Server instance to on.",
	"custom": {"controls": {"CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0": ["CIS-Google-Cloud-Platform-Foundation-Benchmark_v3.0.0_6.3.6"]}, "severity": "Medium", "author": "Starchitect Agent"},
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

# Check if database flags contain trace flag 3625 set to on
has_trace_flag_enabled(instance) {
	flag := instance.settings[_].database_flags[_]
	flag.name == "3625"
	flag.value == "on"
}

# Allow if trace flag 3625 is enabled
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	has_trace_flag_enabled(instance)
	p = fugue.allow_resource(instance)
}

# Deny if trace flag 3625 is not enabled
policy[p] {
	instance := sql_instances[_]
	is_sql_server(instance)
	not has_trace_flag_enabled(instance)
	p = fugue.deny_resource_with_message(
		instance,
		sprintf("Cloud SQL Server instance '%s' must have trace flag 3625 enabled", [instance.name]),
	)
}
