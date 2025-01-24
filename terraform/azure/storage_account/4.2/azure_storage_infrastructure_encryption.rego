package rules.azure_storage_infrastructure_encryption

import data.fugue

__rego__metadoc__ := {
    "id": "4.2",
    "title": "Ensure that 'Enable Infrastructure Encryption' for Each Storage Account in Azure Storage is Set to 'enabled'",
    "description": "Enabling encryption at the hardware level on top of the default software encryption for Storage Accounts accessing Azure storage solutions.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if infrastructure encryption is enabled
is_infrastructure_encryption_enabled(account) {
    account.infrastructure_encryption_enabled == true
}

# Allow storage accounts with infrastructure encryption enabled
policy[p] {
    account := storage_accounts[_]
    is_infrastructure_encryption_enabled(account)
    p = fugue.allow_resource(account)
}

# Deny storage accounts without infrastructure encryption
policy[p] {
    account := storage_accounts[_]
    not is_infrastructure_encryption_enabled(account)
    p = fugue.deny_resource_with_message(account, "Storage account must have infrastructure encryption enabled for enhanced security")
}