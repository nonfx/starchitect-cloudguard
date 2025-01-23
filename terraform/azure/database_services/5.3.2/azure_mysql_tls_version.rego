package rules.mysql_tls_version

import data.fugue

__rego__metadoc__ := {
    "id": "5.3.2",
    "title": "Ensure server parameter 'tls_version' is set to 'TLSv1.2' or higher for MySQL flexible server",
    "description": "MySQL flexible servers must use TLS version 1.2 or higher to ensure secure encrypted connections and prevent man-in-the-middle attacks.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.3.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all MySQL flexible server configurations
mysql_configs = fugue.resources("azurerm_mysql_flexible_server_configuration")

# Helper to check if TLS version is 1.2 or higher
is_valid_tls_version(config) {
    config.name == "tls_version"
    config.value == "TLSv1.2"
}

is_valid_tls_version(config) {
    config.name == "tls_version"
    config.value == "TLSv1.3"
}

# Allow configurations with TLS 1.2 or higher
policy[p] {
    config := mysql_configs[_]
    is_valid_tls_version(config)
    p = fugue.allow_resource(config)
}

# Deny configurations with invalid TLS versions
policy[p] {
    config := mysql_configs[_]
    config.name == "tls_version"
    not is_valid_tls_version(config)
    p = fugue.deny_resource_with_message(config, "MySQL flexible server must use TLS version 1.2 or higher")
}