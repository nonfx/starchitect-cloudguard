package rules.azure_diagnostic_settings_categories

import data.fugue

__rego__metadoc__ := {
    "id": "6.1.2",
    "title": "Ensure Diagnostic Setting captures appropriate categories",
    "description": "The diagnostic setting should be configured to log the appropriate activities from the control/management plane.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_6.1.2"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all diagnostic settings
diagnostic_settings = fugue.resources("azurerm_monitor_diagnostic_setting")

# Helper to check if all required categories are enabled
has_required_categories(setting) {
    categories := {category | category := setting.log[_].category}
    required := {"Administrative", "Alert", "Policy", "Security"}
    missing := required - categories
    count(missing) == 0
}

# Helper to check if categories are enabled
are_categories_enabled(setting) {
    log := setting.log[_]
    log.enabled == true
}

# Allow if all required categories are enabled
policy[p] {
    setting := diagnostic_settings[_]
    has_required_categories(setting)
    are_categories_enabled(setting)
    p = fugue.allow_resource(setting)
}

# Deny if required categories are missing
policy[p] {
    setting := diagnostic_settings[_]
    not has_required_categories(setting)
    p = fugue.deny_resource_with_message(setting, "Diagnostic setting must include Administrative, Alert, Policy, and Security categories")
}

# Deny if categories are disabled
policy[p] {
    setting := diagnostic_settings[_]
    not are_categories_enabled(setting)
    p = fugue.deny_resource_with_message(setting, "All configured diagnostic categories must be enabled")
}