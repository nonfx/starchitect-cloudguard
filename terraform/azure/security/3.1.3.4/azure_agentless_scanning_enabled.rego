package rules.azure_agentless_scanning_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.3.4",
    "title": "Ensure that 'Agentless scanning for machines' component status is set to 'On'",
    "description": "Using disk snapshots, the agentless scanner scans for installed software, vulnerabilities, and plain text secrets.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.3.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center settings
security_center_settings = fugue.resources("azurerm_security_center_setting")

# Helper to check if agentless scanning is enabled
is_agentless_scanning_enabled(setting) {
    setting.setting_name == "MCAS"
    setting.enabled == true
}

# Allow if agentless scanning is enabled
policy[p] {
    setting := security_center_settings[_]
    is_agentless_scanning_enabled(setting)
    p = fugue.allow_resource(setting)
}

# Deny if agentless scanning is disabled
policy[p] {
    setting := security_center_settings[_]
    setting.setting_name == "MCAS"
    not is_agentless_scanning_enabled(setting)
    p = fugue.deny_resource_with_message(setting, "Agentless scanning for machines must be enabled for comprehensive security scanning")
}

# Deny if setting is missing
policy[p] {
    count(security_center_settings) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_setting", "No security center settings found - agentless scanning for machines must be configured")
}