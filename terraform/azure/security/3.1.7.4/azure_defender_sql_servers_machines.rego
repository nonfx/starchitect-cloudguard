package rules.azure_defender_sql_servers_machines

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.7.4",
    "title": "Ensure That Microsoft Defender for SQL Servers on Machines Is Set To 'On'",
    "description": "Turning on Microsoft Defender for SQL servers on machines enables threat detection for SQL servers on machines, providing threat intelligence, anomaly detection, and behavior analytics in Microsoft Defender for Cloud.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.7.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center subscriptions
security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")

# Helper to check if Defender for SQL Servers on Machines is enabled
is_sql_servers_defender_enabled(sub) {
    sub.resource_type == "SqlServerVirtualMachines"
    sub.tier == "Standard"
}

# Allow if Defender for SQL Servers is enabled
policy[p] {
    sub := security_center_subs[_]
    is_sql_servers_defender_enabled(sub)
    p = fugue.allow_resource(sub)
}

# Deny if Defender for SQL Servers is not enabled
policy[p] {
    sub := security_center_subs[_]
    not is_sql_servers_defender_enabled(sub)
    p = fugue.deny_resource_with_message(sub, "Microsoft Defender for SQL Servers on Machines must be enabled with Standard tier")
}

# Deny if no security center subscription pricing is configured
policy[p] {
    count(security_center_subs) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_subscription_pricing", "No Microsoft Defender for SQL Servers configuration found")
}