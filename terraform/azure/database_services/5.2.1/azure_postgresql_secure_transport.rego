package rules.azure_postgresql_secure_transport

import data.fugue

__rego__metadoc__ := {
    "id": "5.2.1",
    "title": "Ensure server parameter 'require_secure_transport' is set to 'ON' for PostgreSQL flexible server",
    "description": "PostgreSQL flexible servers must enforce SSL connections by enabling require_secure_transport parameter for enhanced data security.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.2.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL flexible servers and their configurations
postgresql_servers = fugue.resources("azurerm_postgresql_flexible_server")
postgresql_configurations = fugue.resources("azurerm_postgresql_flexible_server_configuration")

# Helper to check if secure transport is enabled
is_secure_transport_enabled(config) {
    config.name == "require_secure_transport"
    config.value == "ON"
}

# Allow servers with secure transport enabled
policy[p] {
    server := postgresql_servers[_]
    config := postgresql_configurations[_]
    is_secure_transport_enabled(config)
    p = fugue.allow_resource(server)
}

# Deny servers without secure transport enabled
policy[p] {
    server := postgresql_servers[_]
    config := postgresql_configurations[_]
    not is_secure_transport_enabled(config)
    p = fugue.deny_resource_with_message(server, "PostgreSQL flexible server must have require_secure_transport parameter set to ON")
}

# Deny servers with no configuration for secure transport
policy[p] {
    server := postgresql_servers[_]
    not any_secure_transport_config(server.name)
    p = fugue.deny_resource_with_message(server, "PostgreSQL flexible server is missing require_secure_transport parameter configuration")
}

# Helper to check if any secure transport configuration exists for a server
any_secure_transport_config(server_name) {
    config := postgresql_configurations[_]
    config.name == "require_secure_transport"
}