package rules.azure_storage_account_default_network_deny

import data.fugue

__rego__metadoc__ := {
    "id": "4.7",
    "title": "Ensure Default Network Access Rule for Storage Accounts is Set to Deny",
    "description": "Restricting default network access helps to provide a new layer of security, since storage accounts accept connections from clients on any network. To limit access to selected networks, the default action must be changed.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.7"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if default network access is denied
is_default_action_deny(account) {
    account.network_rules[_].default_action == "Deny"
}

# Allow storage accounts with default action set to deny
policy[p] {
    account := storage_accounts[_]
    is_default_action_deny(account)
    p = fugue.allow_resource(account)
}

# Deny storage accounts without default action set to deny
policy[p] {
    account := storage_accounts[_]
    not is_default_action_deny(account)
    p = fugue.deny_resource_with_message(account, "Storage account default network access rule must be set to 'Deny'")
}