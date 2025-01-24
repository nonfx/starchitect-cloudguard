package rules.azure_storage_public_access

import data.fugue

__rego__metadoc__ := {
    "id": "4.6",
    "title": "Ensure that 'Public Network Access' is 'Disabled' for storage accounts",
    "description": "Disallowing public network access for a storage account overrides the public access settings for individual containers in that storage account for Azure Resource Manager Deployment Model storage accounts.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.6"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if public network access is disabled
is_public_access_disabled(account) {
    account.public_network_access_enabled == false
}

# Allow storage accounts with public network access disabled
policy[p] {
    account := storage_accounts[_]
    is_public_access_disabled(account)
    p = fugue.allow_resource(account)
}

# Deny storage accounts with public network access enabled
policy[p] {
    account := storage_accounts[_]
    not is_public_access_disabled(account)
    p = fugue.deny_resource_with_message(account, "Storage account must have public network access disabled for enhanced security")
}
