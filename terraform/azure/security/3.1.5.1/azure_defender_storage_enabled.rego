package rules.azure_defender_storage_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.5.1",
    "title": "Ensure That Microsoft Defender for Storage Is Set To 'On'",
    "description": "Turning on Microsoft Defender for Storage enables threat detection for Storage, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.5.1"]},"severity":"High"},
}

resource_type := "MULTIPLE"

# Get all security center subscriptions
security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Defender for Storage is enabled
is_storage_defender_enabled(sub) {
    sub.resource_type == "StorageAccounts"
    sub.tier == "Standard"
}

# Allow if Defender for Storage is enabled
policy[p] {
    sub := security_center_subs[_]
    is_storage_defender_enabled(sub)
    p = fugue.allow_resource(sub)
}

# Deny if Defender for Storage is not enabled
policy[p] {
    sub := security_center_subs[_]
    not is_storage_defender_enabled(sub)
    p = fugue.deny_resource_with_message(sub, "Microsoft Defender for Storage must be enabled with Standard tier")
}

# Deny if no security center subscription pricing is configured
policy[p] {
    count(security_center_subs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "No Microsoft Defender for Storage configuration found")
}