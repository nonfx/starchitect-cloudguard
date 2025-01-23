package rules.azure_postgres_log_retention

import data.fugue

__rego__metadoc__ := {
    "id": "5.2.4",
    "title": "Ensure server parameter 'logfiles.retention_days' is greater than 3 days",
    "description": "PostgreSQL flexible servers must maintain log files for more than 3 days to enable proper troubleshooting and monitoring.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.2.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL flexible servers and their configurations
postgres_servers = fugue.resources("azurerm_postgresql_flexible_server")
postgres_configurations = fugue.resources("azurerm_postgresql_flexible_server_configuration")

# Helper to check if retention days is greater than 3
is_retention_compliant(config) {
    config.name == "logfiles.retention_days"
    to_number(config.value) > 3
}

# Allow servers with compliant retention period
policy[p] {
    server := postgres_servers[_]
    config := postgres_configurations[_]
    config.server_id == server.id
    is_retention_compliant(config)
    p = fugue.allow_resource(server)
}

# Deny servers with non-compliant retention period
policy[p] {
    server := postgres_servers[_]
    config := postgres_configurations[_]
    config.server_id == server.id
    config.name == "logfiles.retention_days"
    not is_retention_compliant(config)
    p = fugue.deny_resource_with_message(server, "PostgreSQL flexible server log retention period must be greater than 3 days")
}

# Deny servers with missing retention configuration
policy[p] {
    server := postgres_servers[_]
    not has_retention_config(server.id)
    p = fugue.deny_resource_with_message(server, "PostgreSQL flexible server must have logfiles.retention_days configured")
}

# Helper to check if server has retention configuration
has_retention_config(server_id) {
    config := postgres_configurations[_]
    config.server_id == server_id
    config.name == "logfiles.retention_days"
}