package rules.azure_postgres_public_access_disabled

import data.fugue

__rego__metadoc__ := {
    "id": "5.2.5",
    "title": "Ensure public access from Azure services to PostgreSQL flexible server is disabled",
    "description": "PostgreSQL flexible server should not allow public access from all Azure services to enhance security through specific firewall rules.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.2.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all PostgreSQL flexible servers and their firewall rules
postgres_servers = fugue.resources("azurerm_postgresql_flexible_server")
firewall_rules = fugue.resources("azurerm_postgresql_flexible_server_firewall_rule")

# Helper to check if a rule allows all Azure services
is_azure_services_rule(rule) {
    rule.start_ip_address == "0.0.0.0"
    rule.end_ip_address == "0.0.0.0"
}

# Helper to check if server has any Azure services rule
has_azure_services_rule(server) {
    rule := firewall_rules[_]
    rule.server_id == server.id
    is_azure_services_rule(rule)
}

# Allow servers that don't have Azure services rule
policy[p] {
    server := postgres_servers[_]
    not has_azure_services_rule(server)
    p = fugue.allow_resource(server)
}

# Deny servers that have Azure services rule
policy[p] {
    server := postgres_servers[_]
    has_azure_services_rule(server)
    p = fugue.deny_resource_with_message(server, "PostgreSQL flexible server should not allow public access from all Azure services")
}