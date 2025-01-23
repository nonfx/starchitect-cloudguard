package rules.azure_defender_sql_managed_instance

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.7.3",
    "title": "Ensure That Microsoft Defender for (Managed Instance) Azure SQL Databases Is Set To 'On'",
    "description": "Turning on Microsoft Defender for Azure SQL Databases enables threat detection for Managed Instance Azure SQL databases, providing threat intelligence, anomaly detection, and behavior analytics in Microsoft Defender for Cloud.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.7.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center subscriptions
security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Defender for SQL is enabled
is_sql_defender_enabled(sub) {
    sub.resource_type == "SqlServers"
    sub.tier == "Standard"
}

# Allow if Defender for SQL is enabled
policy[p] {
    sub := security_center_subs[_]
    is_sql_defender_enabled(sub)
    p = fugue.allow_resource(sub)
}

# Deny if Defender for SQL is not enabled
policy[p] {
    sub := security_center_subs[_]
    not is_sql_defender_enabled(sub)
    p = fugue.deny_resource_with_message(sub, "Microsoft Defender for Azure SQL Databases must be enabled with Standard tier")
}

# Deny if no security center subscription pricing is configured
policy[p] {
    count(security_center_subs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "No Microsoft Defender for SQL configuration found")
}