package rules.azure_mysql_audit_logging

import data.fugue

__rego__metadoc__ := {
    "id": "5.3.3",
    "title": "Ensure server parameter 'audit_log_enabled' is set to 'ON' for MySQL flexible server",
    "description": "MySQL flexible servers must have audit logging enabled to track server activities and maintain security compliance.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.3.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

mysql_servers[id] = server {
    server := fugue.resources("azurerm_mysql_flexible_server")[id]
}

mysql_configurations[id] = config {
    config := fugue.resources("azurerm_mysql_flexible_server_configuration")[id]
}

is_audit_enabled(config) {
    config.name == "audit_log_enabled"
    config.value == "ON"
}

policy[p] {
    server := mysql_servers[server_id]
    config := mysql_configurations[config_id]
    config.server_name == server.name
    is_audit_enabled(config)
    p = fugue.allow_resource(server)
}

policy[p] {
    server := mysql_servers[server_id]
    config := mysql_configurations[config_id]
    config.server_name == server.name
    not is_audit_enabled(config)
    p = fugue.deny_resource_with_message(server, "MySQL flexible server must have audit_log_enabled parameter set to 'ON'")
}

policy[p] {
    server := mysql_servers[server_id]
    not any_matching_config(server.name)
    p = fugue.deny_resource_with_message(server, "MySQL flexible server must have audit_log_enabled parameter configured")
}

any_matching_config(server_name) {
    mysql_configurations[_].server_name == server_name
}