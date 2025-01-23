package rules.azure_private_endpoints

import data.fugue

__rego__metadoc__ := {
    "id": "5.4.2",
    "title": "Ensure That Private Endpoints Are Used Where Possible",
    "description": "Azure resources should use private endpoints to limit network traffic to approved sources and enhance security.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_5.4.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cosmosdb_accounts = fugue.resources("azurerm_cosmosdb_account")
private_endpoints = fugue.resources("azurerm_private_endpoint")

has_private_endpoint(account) {
    endpoint := private_endpoints[_]
    endpoint.private_service_connection[_].private_connection_resource_id == account.id
}

has_compliant_configuration(account) {
    has_private_endpoint(account)
    account.public_network_access_enabled == false
}

policy[p] {
    account := cosmosdb_accounts[_]
    has_compliant_configuration(account)
    p = fugue.allow_resource(account)
}

policy[p] {
    account := cosmosdb_accounts[_]
    not has_compliant_configuration(account)
    p = fugue.deny_resource_with_message(account, "Cosmos DB account must use private endpoints and disable public network access")
}