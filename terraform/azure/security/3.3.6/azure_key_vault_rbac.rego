package rules.azure_key_vault_rbac

import data.fugue

__rego__metadoc__ := {
    "id": "3.3.6",
    "title": "Enable Role Based Access Control for Azure Key Vault",
    "description": "The recommended way to access Key Vaults is to use the Azure Role-Based Access Control (RBAC) permissions model. Azure RBAC provides fine-grained access management of Azure resources.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.3.6"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Key Vault resources
key_vaults = fugue.resources("azurerm_key_vault")

# Helper to check if RBAC is enabled
is_rbac_enabled(vault) {
    vault.enable_rbac_authorization == true
}

# Allow if RBAC is enabled
policy[p] {
    vault := key_vaults[_]
    is_rbac_enabled(vault)
    p = fugue.allow_resource(vault)
}

# Deny if RBAC is not enabled
policy[p] {
    vault := key_vaults[_]
    not is_rbac_enabled(vault)
    p = fugue.deny_resource_with_message(vault, "Key Vault must have RBAC authorization enabled for fine-grained access control")
}

# Deny if no Key Vault exists
policy[p] {
    count(key_vaults) == 0
    p = fugue.missing_resource_with_message("azurerm_key_vault", "No Key Vault found - Key Vault must be configured with RBAC authorization enabled")
}