package rules.azure_auto_provisioning_monitoring_agent

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.1.1",
    "title": "Ensure Auto provisioning of Log Analytics agent for Azure VMs is Set to On",
    "description": "Enable automatic provisioning of the monitoring agent to collect security data. The Log Analytics Agent will be deprecated in August 2024.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.1.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all auto provisioning settings
auto_provisioning_settings = fugue.resources("azurerm_security_center_auto_provisioning")

# Helper to check if auto provisioning is enabled
is_auto_provisioning_on(setting) {
    setting.auto_provision == "On"
}

# Allow if auto provisioning is enabled
policy[p] {
    setting := auto_provisioning_settings[_]
    is_auto_provisioning_on(setting)
    p = fugue.allow_resource(setting)
}

# Deny if auto provisioning is disabled
policy[p] {
    setting := auto_provisioning_settings[_]
    not is_auto_provisioning_on(setting)
    p = fugue.deny_resource_with_message(setting, "Auto provisioning of Log Analytics agent must be set to 'On'")
}

# Deny if no auto provisioning setting exists
policy[p] {
    count(auto_provisioning_settings) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_auto_provisioning", "No auto provisioning setting found - Log Analytics agent auto provisioning must be configured")
}