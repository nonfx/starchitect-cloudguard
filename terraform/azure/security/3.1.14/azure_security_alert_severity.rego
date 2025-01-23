package rules.azure_security_alert_severity

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.14",
    "title": "Ensure That 'Notify about alerts with the following severity' is Set to 'High'",
    "description": "Enables emailing security alerts to the subscription owner or other designated security contact.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.14"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center contact resources
security_contacts = fugue.resources("azurerm_security_center_contact")

# Helper to check if notifications are properly configured
is_notifications_configured(contact) {
    contact.alert_notifications == true
    contact.alerts_to_admins == true
}

# Allow if notifications are properly configured
policy[p] {
    contact := security_contacts[_]
    is_notifications_configured(contact)
    p = fugue.allow_resource(contact)
}

# Deny if notifications are not properly configured
policy[p] {
    contact := security_contacts[_]
    not is_notifications_configured(contact)
    p = fugue.deny_resource_with_message(contact, "Both alert_notifications and alerts_to_admins must be enabled for security contacts")
}

# Deny if no security center contact exists
policy[p] {
    count(security_contacts) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_contact", "No security center contact found - security contact must be configured with notifications enabled")
}