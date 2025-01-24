package rules.azure_storage_secure_transfer

import data.fugue

__rego__metadoc__ := {
    "id": "4.1",
    "title": "Ensure that 'Secure transfer required' is set to 'Enabled'",
    "description": "Enable data encryption in transit by ensuring secure transfer is required for all Azure Storage Accounts.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if secure transfer is enabled
is_secure_transfer_enabled(account) {
    account.https_traffic_only_enabled == true
}

# Allow storage accounts with secure transfer enabled
policy[p] {
    account := storage_accounts[_]
    is_secure_transfer_enabled(account)
    p = fugue.allow_resource(account)
}

# Deny storage accounts without secure transfer enabled
policy[p] {
    account := storage_accounts[_]
    not is_secure_transfer_enabled(account)
    p = fugue.deny_resource_with_message(account, "Storage account must have secure transfer (HTTPS) enabled")
}
