package rules.azure_key_vault_recoverable

import data.fugue

__rego__metadoc__ := {
    "id": "3.3.5",
    "title": "Ensure the Key Vault is Recoverable",
    "description": "The Key Vault contains object keys secrets and certificates. Accidental unavailability of a Key Vault can cause immediate data loss or loss of security functions. It is recommended to enable both 'Do Not Purge' and 'Soft Delete' functions.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.3.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Key Vault resources
key_vaults = fugue.resources("azurerm_key_vault")

# Helper to check if vault has required protection features
is_recoverable(vault) {
    vault.purge_protection_enabled == true
    vault.soft_delete_retention_days >= 7
}

# Allow if both protections are properly configured
policy[p] {
    vault := key_vaults[_]
    is_recoverable(vault)
    p = fugue.allow_resource(vault)
}

# Deny if any protection feature is missing or misconfigured
policy[p] {
    vault := key_vaults[_]
    not is_recoverable(vault)
    message := get_violation_message(vault)
    p = fugue.deny_resource_with_message(vault, message)
}

# Helper to generate appropriate violation message
get_violation_message(vault) = msg {
    not vault.purge_protection_enabled
    not vault.soft_delete_retention_days >= 7
    msg = "Key Vault must have both purge protection enabled and soft delete retention days >= 7"
} else = msg {
    not vault.purge_protection_enabled
    msg = "Key Vault must have purge protection enabled"
} else = msg {
    not vault.soft_delete_retention_days >= 7
    msg = "Key Vault must have soft delete retention days >= 7"
}

# Deny if no Key Vault exists
policy[p] {
    count(key_vaults) == 0
    p = fugue.missing_resource_with_message("azurerm_key_vault", "No Key Vault found")
}