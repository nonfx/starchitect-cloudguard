package rules.azure_defender_opensource_relational_db

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.7.2",
    "title": "Ensure That Microsoft Defender for Open-Source Relational Databases Is Set To 'On'",
    "description": "Turning on Microsoft Defender for Open-source relational databases enables threat detection for Open-source relational databases, providing threat intelligence, anomaly detection, and behavior analytics in the Microsoft Defender for Cloud.",
    "custom": {
        "controls": {"CIS-Azure_v3.0.0": ["CIS-Azure_v3.0.0_3.1.7.2"]},
        "severity": "Medium"
    },
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.7.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center subscriptions
security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Defender for Open-source relational databases is enabled
is_defender_enabled(sub) {
    sub.resource_type == "OpenSourceRelationalDatabases"
    sub.tier == "Standard"
}

# Allow if Defender is enabled
policy[p] {
    sub := security_center_subs[_]
    is_defender_enabled(sub)
    p = fugue.allow_resource(sub)
}

# Deny if Defender is not enabled
policy[p] {
    sub := security_center_subs[_]
    not is_defender_enabled(sub)
    p = fugue.deny_resource_with_message(sub, "Microsoft Defender for Open-source relational databases must be enabled with Standard tier")
}

# Deny if no security center subscription pricing is configured
policy[p] {
    count(security_center_subs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "No Microsoft Defender for Open-source relational databases configuration found")
}