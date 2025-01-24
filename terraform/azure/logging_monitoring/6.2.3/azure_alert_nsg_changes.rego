package rules.azure_alert_nsg_changes

import data.fugue

__rego__metadoc__ := {
    "id": "6.2.3",
    "title": "Ensure that Activity Log Alert exists for Create or Update Network Security Group",
    "description": "Create an Activity Log Alert for the Create or Update Network Security Group event.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_6.2.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all monitor activity log alert resources
activity_alerts = fugue.resources("azurerm_monitor_activity_log_alert")

# Helper to check if alert is properly configured for NSG changes
is_properly_configured(alert) {
    alert.enabled == true

    # Check for NSG create/update operation
    some i
    criteria = alert.criteria[i]
    criteria.operation_name == "Microsoft.Network/networkSecurityGroups/write"
    criteria.category == "Administrative"
}

# Allow if properly configured alert exists
policy[p] {
    alert = activity_alerts[_]
    is_properly_configured(alert)
    p = fugue.allow_resource(alert)
}

# Deny if no properly configured alert exists
policy[p] {
    count(activity_alerts) == 0
    p = fugue.missing_resource_with_message(
        "azurerm_monitor_activity_log_alert",
        "No activity log alert found for Network Security Group create/update events"
    )
}

# Deny alerts that are not properly configured
policy[p] {
    alert = activity_alerts[_]
    not is_properly_configured(alert)
    p = fugue.deny_resource_with_message(
        alert,
        "Activity log alert is not properly configured for Network Security Group create/update events"
    )
}