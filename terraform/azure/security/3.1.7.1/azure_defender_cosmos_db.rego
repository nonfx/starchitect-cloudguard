package rules.azure_defender_cosmos_db

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.7.1",
    "title": "Ensure That Microsoft Defender for Azure Cosmos DB Is Set To 'On'",
    "description": "Microsoft Defender for Azure Cosmos DB scans all incoming network requests for threats to your Azure Cosmos DB resources.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.7.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center subscriptions
security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Defender for Cosmos DB is enabled
is_cosmos_db_defender_enabled(sub) {
    sub.resource_type == "CosmosDbs"
    sub.tier == "Standard"
}

# Allow if Defender for Cosmos DB is enabled
policy[p] {
    sub := security_center_subs[_]
    is_cosmos_db_defender_enabled(sub)
    p = fugue.allow_resource(sub)
}

# Deny if Defender for Cosmos DB is not enabled
policy[p] {
    sub := security_center_subs[_]
    not is_cosmos_db_defender_enabled(sub)
    p = fugue.deny_resource_with_message(sub, "Microsoft Defender for Azure Cosmos DB must be enabled (set to Standard tier)")
}

# Deny if no security center subscription pricing is configured
policy[p] {
    count(security_center_subs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "No Microsoft Defender for Cosmos DB configuration found")
}