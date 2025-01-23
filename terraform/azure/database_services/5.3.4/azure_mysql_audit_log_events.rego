package rules.azure_mysql_audit_log_events

import data.fugue

__rego__metadoc__ := {
    "id": "5.3.4",
    "title": "Ensure server parameter 'audit_log_events' has 'CONNECTION' set for MySQL flexible server",
    "description": "MySQL flexible servers must have audit_log_events parameter configured to include CONNECTION for logging server access attempts.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.3.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

mysql_servers[id] = server {
    server := fugue.resources("azurerm_mysql_flexible_server")[id]
}

mysql_configurations[id] = config {
    config := fugue.resources("azurerm_mysql_flexible_server_configuration")[id]
}

# Helper to check if CONNECTION is included in audit_log_events
has_connection_audit(config) {
    config.name == "audit_log_events"
    contains(lower(config.value), "connection")
}

# Allow servers with CONNECTION in audit_log_events
policy[p] {
    server := mysql_servers[server_id]
    config := mysql_configurations[config_id]
    config.server_name == server.name
    has_connection_audit(config)
    p = fugue.allow_resource(server)
}

# Deny servers without CONNECTION in audit_log_events
policy[p] {
    server := mysql_servers[server_id]
    config := mysql_configurations[config_id]
    config.server_name == server.name
    not has_connection_audit(config)
    p = fugue.deny_resource_with_message(server, "MySQL flexible server must have CONNECTION included in audit_log_events parameter")
}

# Deny servers with no audit_log_events configuration
policy[p] {
    server := mysql_servers[server_id]
    not any_matching_config(server.name)
    p = fugue.deny_resource_with_message(server, "MySQL flexible server must have audit_log_events parameter configured")
}

any_matching_config(server_name) {
    mysql_configurations[_].server_name == server_name
}