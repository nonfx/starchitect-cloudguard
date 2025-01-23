package rules.azure_sql_entra_auth

import data.fugue

__rego__metadoc__ := {
    "id": "5.1.4",
    "title": "Ensure Microsoft Entra authentication is Configured for SQL Servers",
    "description": "Use Microsoft Entra authentication for authentication with SQL Database to manage credentials in a single place.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.1.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all SQL servers
sql_servers = fugue.resources("azurerm_mssql_server")

# Helper to check if AD admin is configured
has_ad_admin(server) {
    server.azuread_administrator != null
    server.azuread_administrator[_].login_username != null
    server.azuread_administrator[_].object_id != null
}

# Allow servers with AD admin configured
policy[p] {
    server := sql_servers[_]
    has_ad_admin(server)
    p = fugue.allow_resource(server)
}

# Deny servers without AD admin configured
policy[p] {
    server := sql_servers[_]
    not has_ad_admin(server)
    p = fugue.deny_resource_with_message(server, "SQL Server must have Microsoft Entra authentication configured with an administrator")
}