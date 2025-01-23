package rules.azure_defender_resource_manager

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.9.1",
    "title": "Ensure That Microsoft Defender for Resource Manager Is Set To 'On'",
    "description": "Microsoft Defender for Resource Manager scans incoming administrative requests to change your infrastructure from both CLI and the Azure portal.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.9.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center subscriptions
security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Resource Manager protection is enabled
is_resource_manager_enabled(sub) {
    sub.resource_type == "Arm"
    sub.tier == "Standard"
}

# Allow if Resource Manager protection is enabled
policy[p] {
    sub := security_center_subs[_]
    is_resource_manager_enabled(sub)
    p = fugue.allow_resource(sub)
}

# Deny if Resource Manager protection is not enabled
policy[p] {
    sub := security_center_subs[_]
    not is_resource_manager_enabled(sub)
    p = fugue.deny_resource_with_message(sub, "Microsoft Defender for Resource Manager must be enabled with Standard tier")
}

# Deny if no security center subscription pricing is configured
policy[p] {
    count(security_center_subs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "No Microsoft Defender for Resource Manager configuration found")
}