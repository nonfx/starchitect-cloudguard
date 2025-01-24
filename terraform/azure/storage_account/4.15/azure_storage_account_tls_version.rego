package rules.storage_account_tls_version

import data.fugue

__rego__metadoc__ := {
    "id": "4.15",
    "title": "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'",
    "description": "Azure storage accounts must enforce TLS 1.2 as minimum protocol version to protect data in transit.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.15"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all storage accounts
storage_accounts = fugue.resources("azurerm_storage_account")

# Helper to check if minimum TLS version is 1.2
has_minimum_tls_version(account) {
    account.min_tls_version == "TLS1_2"
}

# Allow if minimum TLS version is 1.2
policy[p] {
    account := storage_accounts[_]
    has_minimum_tls_version(account)
    p = fugue.allow_resource(account)
}

# Deny if minimum TLS version is not 1.2
policy[p] {
    account := storage_accounts[_]
    not has_minimum_tls_version(account)
    p = fugue.deny_resource_with_message(account, "Storage account must have minimum TLS version set to 1.2")
}