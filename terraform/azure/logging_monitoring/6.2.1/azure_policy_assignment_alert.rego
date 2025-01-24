package rules.azure_policy_assignment_alert

import data.fugue

__rego__metadoc__ := {
    "id": "6.2.1",
    "title": "Ensure that Activity Log Alert exists for Create Policy Assignment",
    "description": "Create an activity log alert for the Create Policy Assignment event.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_6.2.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all monitor activity log alert resources
activity_alerts = fugue.resources("azurerm_monitor_activity_log_alert")

# Helper to check if alert is properly configured for policy assignments
is_policy_assignment_alert(alert) {
    # Check if the alert is enabled
    alert.enabled == true

    # Check for policy assignment operation in criteria
    criteria = alert.criteria[_]
    criteria.operation_name == "Microsoft.Authorization/policyAssignments/write"
    criteria.category == "Administrative"
}

# Allow if at least one properly configured alert exists
policy[p] {
    count(activity_alerts) > 0
    alert := activity_alerts[_]
    is_policy_assignment_alert(alert)
    p = fugue.allow_resource(alert)
}

# Deny if no properly configured alert exists
policy[p] {
    count(activity_alerts) == 0
    p = fugue.missing_resource_with_message(
        "azurerm_monitor_activity_log_alert",
        "No activity log alert found for Create Policy Assignment events")
}

# Deny alerts that are not properly configured
policy[p] {
    alert := activity_alerts[_]
    not is_policy_assignment_alert(alert)
    p = fugue.deny_resource_with_message(
        alert,
        "Activity log alert must monitor Microsoft.Authorization/policyAssignments/write operations")
}
