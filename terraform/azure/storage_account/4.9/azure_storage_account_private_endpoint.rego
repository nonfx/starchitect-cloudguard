package rules.storage_account_private_endpoint

import data.fugue

__rego__metadoc__ := {
    "id": "4.9",
    "title": "Ensure Private Endpoints are used to access Storage Accounts",
    "description": "Storage accounts must use private endpoints to enable secure, encrypted data access through VNet connections.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_4.9"]},"severity":"High"},
}

resource_type := "MULTIPLE"

storage_accounts = fugue.resources("azurerm_storage_account")
private_endpoints = fugue.resources("azurerm_private_endpoint")

has_private_endpoint(account) {
    endpoint := private_endpoints[_]
    endpoint.private_service_connection[_].private_connection_resource_id == account.id
}

is_public_access_disabled(account) {
    account.public_network_access_enabled == false
}

# Allow if both conditions are met
policy[p] {
    account := storage_accounts[_]
    has_private_endpoint(account)
    is_public_access_disabled(account)
    p = fugue.allow_resource(account)
}

# Deny if private endpoint is missing
policy[p] {
    account := storage_accounts[_]
    not has_private_endpoint(account)
    p = fugue.deny_resource_with_message(account, "Private endpoint must be configured")
}

# Deny if public network access is enabled
policy[p] {
    account := storage_accounts[_]
    not is_public_access_disabled(account)
    p = fugue.deny_resource_with_message(account, "Public network access must be disabled")
}