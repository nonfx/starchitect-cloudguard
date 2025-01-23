package rules.azure_key_vault_private_endpoint

import data.fugue

__rego__metadoc__ := {
    "id": "3.3.7",
    "title": "Ensure that Private Endpoints are Used for Azure Key Vault",
    "description": "Private endpoints will secure network traffic from Azure Key Vault to the resources requesting secrets and keys.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.3.7"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Key Vault and Private Endpoint resources
key_vaults = fugue.resources("azurerm_key_vault")
private_endpoints = fugue.resources("azurerm_private_endpoint")

# Helper to check if vault has associated private endpoint
has_private_endpoint(vault) {
    endpoint := private_endpoints[_]
    endpoint.private_service_connection[_].private_connection_resource_id == vault.id
    endpoint.private_service_connection[_].subresource_names[_] == "vault"
}

# Allow if vault has private endpoint
policy[p] {
    vault := key_vaults[_]
    has_private_endpoint(vault)
    p = fugue.allow_resource(vault)
}

# Deny if vault has no private endpoint
policy[p] {
    vault := key_vaults[_]
    not has_private_endpoint(vault)
    p = fugue.deny_resource_with_message(vault, "Key Vault must have a private endpoint configured")
}

# Deny if no Key Vault exists
policy[p] {
    count(key_vaults) == 0
    p = fugue.missing_resource_with_message("azurerm_key_vault", "No Key Vault found - Key Vault must be configured with private endpoint")
}