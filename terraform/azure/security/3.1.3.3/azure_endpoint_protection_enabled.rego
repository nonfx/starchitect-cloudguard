package rules.azure_endpoint_protection_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.3.3",
    "title": "Ensure that 'Endpoint protection' component status is set to 'On'",
    "description": "The Endpoint protection component enables Microsoft Defender for Endpoint to communicate with Microsoft Defender for Cloud, providing comprehensive endpoint detection and response capabilities.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.3.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center settings
security_center_settings = fugue.resources("azurerm_security_center_setting")

# Helper to check if endpoint protection is enabled
is_endpoint_protection_enabled(setting) {
    setting.setting_name == "WDATP"
    setting.enabled == true
}

# Allow if endpoint protection is enabled
policy[p] {
    setting := security_center_settings[_]
    is_endpoint_protection_enabled(setting)
    p = fugue.allow_resource(setting)
}

# Deny if endpoint protection is disabled
policy[p] {
    setting := security_center_settings[_]
    setting.setting_name == "WDATP"
    not is_endpoint_protection_enabled(setting)
    p = fugue.deny_resource_with_message(setting, "Endpoint protection must be enabled in Microsoft Defender for Cloud")
}

# Deny if endpoint protection setting is missing
policy[p] {
    count(security_center_settings) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_setting", "No Endpoint protection setting found - must be configured and enabled")
}