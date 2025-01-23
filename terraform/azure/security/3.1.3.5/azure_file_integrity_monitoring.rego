package rules.azure_file_integrity_monitoring

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.3.5",
    "title": "Ensure that File Integrity Monitoring component status is set to 'On'",
    "description": "File Integrity Monitoring (FIM) is a feature that monitors critical system files in Windows or Linux for potential signs of attack or compromise.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.3.5"]},"severity":"High"},
}

resource_type := "MULTIPLE"

# Get relevant resources
security_center_subs = fugue.resources("azurerm_security_center_subscription_pricing")
security_center_settings = fugue.resources("azurerm_security_center_setting")

# Check if Defender Plan 2 is enabled
is_defender_plan2_enabled(subscription) {
    subscription.tier == "Standard"
    subscription.resource_type == "VirtualMachines"
    subscription.subplan == "P2"
}

# Check if FIM setting is enabled
is_fim_enabled(setting) {
    setting.setting_name == "FileIntegrity"
    setting.enabled == true
}

# Allow if both conditions are met
policy[p] {
    subscription := security_center_subs[_]
    setting := security_center_settings[_]
    is_defender_plan2_enabled(subscription)
    is_fim_enabled(setting)
    p = fugue.allow_resource(subscription)
}

# Deny if Defender Plan 2 is not enabled
policy[p] {
    subscription := security_center_subs[_]
    not is_defender_plan2_enabled(subscription)
    p = fugue.deny_resource_with_message(subscription, "Defender for Servers Plan 2 must be enabled for File Integrity Monitoring")
}

# Deny if FIM setting is not enabled
policy[p] {
    setting := security_center_settings[_]
    not is_fim_enabled(setting)
    p = fugue.deny_resource_with_message(setting, "File Integrity Monitoring setting must be enabled")
}