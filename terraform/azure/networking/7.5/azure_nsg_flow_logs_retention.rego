package rules.azure_nsg_flow_logs_retention

import data.fugue

__rego__metadoc__ := {
    "id": "7.5",
    "title": "Ensure that Network Security Group Flow Log retention period is 'greater than 90 days'",
    "description": "Network Security Group Flow Logs should be enabled and the retention period set to greater than or equal to 90 days.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_7.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all NSG flow logs
flow_logs = fugue.resources("azurerm_network_watcher_flow_log")

# Helper to check if retention policy is compliant
is_compliant_retention(flow_log) {
    # Check if flow log is enabled
    flow_log.enabled == true

    # Check retention policy exists
    flow_log.retention_policy[_].enabled == true

    # Check retention days >= 90
    flow_log.retention_policy[_].days >= 90
}

# Allow flow logs with compliant retention
policy[p] {
    flow_log := flow_logs[_]
    is_compliant_retention(flow_log)
    p = fugue.allow_resource(flow_log)
}

# Deny flow logs with non-compliant retention
policy[p] {
    flow_log := flow_logs[_]
    not is_compliant_retention(flow_log)
    p = fugue.deny_resource_with_message(flow_log,
        "Network Security Group Flow Log must be enabled with retention period >= 90 days")
}
