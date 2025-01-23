package rules.azure_postgresql_log_checkpoints

import data.fugue

__rego__metadoc__ := {
    "id": "5.2.2",
    "title": "Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL flexible server",
    "description": "PostgreSQL flexible servers must enable log_checkpoints parameter to track and log checkpoints for monitoring and troubleshooting purposes.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.2.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL flexible server configurations
configurations = fugue.resources("azurerm_postgresql_flexible_server_configuration")

# Helper to check if log_checkpoints is enabled
is_log_checkpoints_enabled(config) {
    config.name == "log_checkpoints"
    config.value == "on"
}

# Allow configurations with log_checkpoints enabled
policy[p] {
    config := configurations[_]
    is_log_checkpoints_enabled(config)
    p = fugue.allow_resource(config)
}

# Deny configurations with log_checkpoints disabled
policy[p] {
    config := configurations[_]
    config.name == "log_checkpoints"
    not is_log_checkpoints_enabled(config)
    p = fugue.deny_resource_with_message(config, "PostgreSQL flexible server parameter 'log_checkpoints' must be set to 'ON'")
}