package rules.azure_keyvault_secret_expiration

import data.fugue

__rego__metadoc__ := {
    "id": "3.3.4",
    "title": "Ensure that the Expiration Date is set for all Secrets in Non-RBAC Key Vaults",
    "description": "Ensure that all Secrets in Non Role Based Access Control (RBAC) Azure Key Vaults have an expiration date set.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.3.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all key vault secrets
keyvault_secrets = fugue.resources("azurerm_key_vault_secret")

# Get all key vaults
key_vaults = fugue.resources("azurerm_key_vault")

# Helper to check if expiration date is set
has_expiration(secret) {
    secret.expiration_date != null
    secret.expiration_date != ""
}

# Helper to check if key vault is non-RBAC
is_non_rbac_vault(vault) {
    not vault.enable_rbac_authorization
}

# Allow secrets with expiration date in non-RBAC vaults
policy[p] {
    secret := keyvault_secrets[_]
    vault := key_vaults[_]
    is_non_rbac_vault(vault)
    has_expiration(secret)
    p = fugue.allow_resource(secret)
}

# Deny secrets without expiration date in non-RBAC vaults
policy[p] {
    secret := keyvault_secrets[_]
    vault := key_vaults[_]
    is_non_rbac_vault(vault)
    not has_expiration(secret)
    p = fugue.deny_resource_with_message(secret, "Key Vault secret must have an expiration date set")
}
