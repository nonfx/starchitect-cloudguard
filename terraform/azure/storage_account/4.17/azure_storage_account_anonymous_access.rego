package rules.storage_account_anonymous_access

import data.fugue

__rego__metadoc__ := {
    "id": "4.17",
    "title": "Ensure that 'Allow Blob Anonymous Access' is set to 'Disabled'",
    "description": "Azure storage accounts must disable anonymous blob access to prevent unauthorized data access and potential security breaches.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.17"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if anonymous access is disabled
is_anonymous_access_disabled(account) {
    account.allow_blob_public_access == false
}

# Allow if anonymous access is disabled
policy[p] {
    account := storage_accounts[_]
    is_anonymous_access_disabled(account)
    p = fugue.allow_resource(account)
}

# Deny if anonymous access is enabled or not explicitly disabled
policy[p] {
    account := storage_accounts[_]
    not is_anonymous_access_disabled(account)
    p = fugue.deny_resource_with_message(account, "Storage account must have 'Allow Blob Anonymous Access' set to 'Disabled' to prevent unauthorized access")
}