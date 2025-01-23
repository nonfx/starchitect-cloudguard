package rules.azure_sql_server_auditing_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "5.1.1",
    "title": "Ensure that 'Auditing' is set to 'On' for Azure SQL Servers",
    "description": "Enable auditing on SQL Servers to track database events and maintain regulatory compliance through audit logs.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.1.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all SQL servers
sql_servers = fugue.resources("azurerm_mssql_server")

# Get all SQL server extended auditing policies
auditing_policies = fugue.resources("azurerm_mssql_server_extended_auditing_policy")

# Helper to check if server has associated auditing policy
has_auditing_policy(server) {
    policy := auditing_policies[_]
    policy.server_id == server.id
    policy.enabled == true
    policy.retention_in_days >= 90
}

# Allow servers with enabled auditing
policy[p] {
    server := sql_servers[_]
    has_auditing_policy(server)
    p = fugue.allow_resource(server)
}

# Deny servers without auditing
policy[p] {
    server := sql_servers[_]
    not has_auditing_policy(server)
    p = fugue.deny_resource_with_message(server, "SQL Server must have auditing enabled with minimum 90 days retention period")
}