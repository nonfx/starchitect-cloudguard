package rules.azure_postgres_connection_throttle

import data.fugue

__rego__metadoc__ := {
    "id": "5.2.3",
    "title": "Ensure server parameter 'connection_throttle.enable' is set to 'ON' for PostgreSQL flexible server",
    "description": "PostgreSQL flexible servers must enable connection throttling to prevent DoS attacks and resource exhaustion through connection management.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.2.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL flexible server configurations
postgres_configs = fugue.resources("azurerm_postgresql_flexible_server_configuration")

# Helper to check if connection throttling is enabled
is_throttling_enabled(config) {
    config.name == "connection_throttle.enable"
    config.value == "on"
}

# Allow configurations with connection throttling enabled
policy[p] {
    config := postgres_configs[_]
    is_throttling_enabled(config)
    p = fugue.allow_resource(config)
}

# Deny configurations without connection throttling enabled
policy[p] {
    config := postgres_configs[_]
    config.name == "connection_throttle.enable"
    not is_throttling_enabled(config)
    p = fugue.deny_resource_with_message(config, "PostgreSQL flexible server must have connection_throttle.enable set to 'ON'")
}