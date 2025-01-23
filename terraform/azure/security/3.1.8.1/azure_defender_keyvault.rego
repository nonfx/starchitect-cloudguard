package rules.azure_defender_keyvault

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.8.1",
    "title": "Ensure That Microsoft Defender for Key Vault Is Set To 'On'",
    "description": "Turning on Microsoft Defender for Key Vault enables threat detection for Key Vault, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.8.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center subscriptions
security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Defender for Key Vault is enabled
is_keyvault_defender_enabled(sub) {
    sub.resource_type == "KeyVaults"
    sub.tier == "Standard"
}

# Allow if Defender for Key Vault is enabled
policy[p] {
    sub := security_center_subs[_]
    is_keyvault_defender_enabled(sub)
    p = fugue.allow_resource(sub)
}

# Deny if Defender for Key Vault is not enabled
policy[p] {
    sub := security_center_subs[_]
    not is_keyvault_defender_enabled(sub)
    p = fugue.deny_resource_with_message(sub, "Microsoft Defender for Key Vault must be enabled with Standard tier pricing")
}

# Deny if no security center subscription pricing is configured
policy[p] {
    count(security_center_subs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "No Microsoft Defender for Key Vault configuration found")
}