package rules.azure_keyvault_key_expiration

import data.fugue

__rego__metadoc__ := {
    "id": "3.3.2",
    "title": "Ensure that the Expiration Date is set for all Keys in Non-RBAC Key Vaults",
    "description": "Ensure that all Keys in Non Role Based Access Control (RBAC) Azure Key Vaults have an expiration date set.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.3.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all key vault keys
keyvault_keys = fugue.resources("azurerm_key_vault_key")

# Helper to check if expiration date is set
has_expiration_date(key) {
    key.expiration_date != null
    key.expiration_date != ""
}

# Allow if expiration date is set
policy[p] {
    key := keyvault_keys[_]
    has_expiration_date(key)
    p = fugue.allow_resource(key)
}

# Deny if expiration date is not set
policy[p] {
    key := keyvault_keys[_]
    not has_expiration_date(key)
    p = fugue.deny_resource_with_message(key, "Key Vault key must have an expiration date set")
}

# Deny if no keys exist
policy[p] {
    count(keyvault_keys) == 0
    p = fugue.missing_resource_with_message("azurerm_key_vault_key", "No Key Vault keys found - keys must be configured with expiration dates")
}