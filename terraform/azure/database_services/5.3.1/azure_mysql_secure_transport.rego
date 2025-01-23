package rules.mysql_secure_transport

import data.fugue

__rego__metadoc__ := {
    "id": "5.3.1",
    "title": "Ensure server parameter 'require_secure_transport' is set to 'ON' for MySQL flexible server",
    "description": "MySQL flexible servers must enforce SSL connections by setting require_secure_transport parameter to 'ON' to protect data in transit.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.3.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all MySQL flexible server configurations
configurations = fugue.resources("azurerm_mysql_flexible_server_configuration")

# Helper to check if secure transport is enabled
is_secure_transport_enabled(config) {
    config.name == "require_secure_transport"
    config.value == "ON"
}

# Allow configurations with secure transport enabled
policy[p] {
    config := configurations[_]
    is_secure_transport_enabled(config)
    p = fugue.allow_resource(config)
}

# Deny configurations without secure transport enabled
policy[p] {
    config := configurations[_]
    config.name == "require_secure_transport"
    not is_secure_transport_enabled(config)
    p = fugue.deny_resource_with_message(config, "MySQL flexible server must have require_secure_transport parameter set to 'ON'")
}