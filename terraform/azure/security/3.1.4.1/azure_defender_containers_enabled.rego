package rules.azure_defender_containers_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.4.1",
    "title": "Ensure That Microsoft Defender for Containers Is Set To 'On'",
    "description": "Turning on Microsoft Defender for Containers enables threat detection for Container Registries including Kubernetes, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.4.1"]},"severity":"High"},
}

resource_type := "MULTIPLE"

# Get all Microsoft Defender pricing resources
defender_pricing = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Containers defender is enabled
is_containers_enabled(pricing) {
    pricing.resource_type == "Containers"
    pricing.tier == "Standard"
}

# Allow if Containers defender is enabled
policy[p] {
    pricing := defender_pricing[_]
    is_containers_enabled(pricing)
    p = fugue.allow_resource(pricing)
}

# Deny if Containers defender is not enabled or set to Free tier
policy[p] {
    pricing := defender_pricing[_]
    pricing.resource_type == "Containers"
    not is_containers_enabled(pricing)
    p = fugue.deny_resource_with_message(pricing, "Microsoft Defender for Containers must be enabled with Standard tier pricing")
}

# Deny if no Containers defender pricing is configured
policy[p] {
    count(defender_pricing) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "Microsoft Defender for Containers pricing configuration is missing")
}