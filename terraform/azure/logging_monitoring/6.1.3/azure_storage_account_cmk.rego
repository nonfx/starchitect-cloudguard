package rules.azure_storage_account_cmk

import data.fugue

__rego__metadoc__ := {
    "id": "6.1.3",
    "title": "Storage account containing activity logs should be encrypted with CMK",
    "description": "Storage accounts with activity log exports must be encrypted using Customer Managed Keys (CMK) to enhance data protection and control.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_6.1.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if CMK encryption is properly configured
is_cmk_configured(account) {
    account.customer_managed_key[_].key_vault_key_id != null
    account.customer_managed_key[_].key_vault_key_id != ""
}

# Allow storage accounts with CMK encryption
policy[p] {
    account := storage_accounts[_]
    is_cmk_configured(account)
    p = fugue.allow_resource(account)
}

# Deny storage accounts without CMK encryption
policy[p] {
    account := storage_accounts[_]
    not is_cmk_configured(account)
    p = fugue.deny_resource_with_message(account, "Storage account must be encrypted with Customer Managed Keys (CMK)")
}