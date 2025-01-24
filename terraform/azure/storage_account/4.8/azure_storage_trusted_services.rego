package rules.azure_storage_trusted_services

import data.fugue

__rego__metadoc__ := {
    "id": "4.8",
    "title": "Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled",
    "description": "Storage accounts must enable trusted Azure services access through network exceptions while maintaining secure firewall configurations.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.8"]},"severity":"High"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if trusted services access is enabled
has_trusted_services_enabled(account) {
    account.network_rules[_].bypass[_] == "AzureServices"
}

# Helper to check if default network access is properly restricted
is_network_access_restricted(account) {
    account.network_rules[_].default_action == "Deny"
}

# Allow if both conditions are met
policy[p] {
    account := storage_accounts[_]
    has_trusted_services_enabled(account)
    is_network_access_restricted(account)
    p = fugue.allow_resource(account)
}

# Deny if trusted services access is not enabled
policy[p] {
    account := storage_accounts[_]
    not has_trusted_services_enabled(account)
    p = fugue.deny_resource_with_message(account, "Storage account must allow trusted Azure services access")
}

# Deny if default network access is not restricted
policy[p] {
    account := storage_accounts[_]
    not is_network_access_restricted(account)
    p = fugue.deny_resource_with_message(account, "Default network access must be set to 'Deny'")
}