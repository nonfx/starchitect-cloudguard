package rules.ensure_defender_servers_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.3.1",
    "title": "Ensure That Microsoft Defender for Servers Is Set to 'On'",
    "description": "Turning on Microsoft Defender for Servers enables threat detection for Servers, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.3.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center pricing configurations
pricing_configs = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Servers plan is enabled
is_servers_enabled(config) {
    config.resource_type == "VirtualMachines"
    config.tier == "Standard"
}

# Allow if Servers plan is enabled
policy[p] {
    config := pricing_configs[_]
    is_servers_enabled(config)
    p = fugue.allow_resource(config)
}

# Deny if Servers plan is disabled or set to Free tier
policy[p] {
    config := pricing_configs[_]
    config.resource_type == "VirtualMachines"
    not is_servers_enabled(config)
    p = fugue.deny_resource_with_message(config, "Microsoft Defender for Servers must be enabled (Standard tier) for enhanced security")
}

# Deny if Servers pricing configuration is missing
policy[p] {
    count(pricing_configs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "Microsoft Defender for Servers pricing configuration is missing")
}