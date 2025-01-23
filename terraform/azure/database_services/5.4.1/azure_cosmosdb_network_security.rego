package rules.azure_cosmosdb_network_security

import data.fugue

__rego__metadoc__ := {
    "id": "5.4.1",
    "title": "Ensure Cosmos DB 'Firewalls & Networks' is limited to selected networks",
    "description": "Cosmos DB accounts should be configured to use specific virtual networks rather than allowing all network access to reduce the attack surface.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.4.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Cosmos DB accounts
cosmosdb_accounts = fugue.resources("azurerm_cosmosdb_account")

# Helper to check if network access is properly restricted
is_network_restricted(account) {
    # Check if public network access is disabled
    not account.public_network_access_enabled
}

is_network_restricted(account) {
    # Check if virtual network filter is enabled and has rules
    account.is_virtual_network_filter_enabled == true
    count(account.virtual_network_rules) > 0
}

# Allow accounts with restricted network access
policy[p] {
    account := cosmosdb_accounts[_]
    is_network_restricted(account)
    p = fugue.allow_resource(account)
}

# Deny accounts with unrestricted network access
policy[p] {
    account := cosmosdb_accounts[_]
    not is_network_restricted(account)
    p = fugue.deny_resource_with_message(account, "Cosmos DB account must be configured to use selected networks instead of allowing all networks")
}