package rules.azure_security_contact_email

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.13",
    "title": "Ensure 'Additional email addresses' is Configured with a Security Contact Email",
    "description": "Microsoft Defender for Cloud emails the subscription owners whenever a high-severity alert is triggered for their subscription. You should provide a security contact email address as an additional email address.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.13"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center contact resources
security_contacts = fugue.resources("azurerm_security_center_contact")

# Helper to check if configuration is valid
is_valid_configuration(contact) {
    contact.email != ""
    contact.alert_notifications == true
    contact.alerts_to_admins == true
}

# Allow if all requirements are met
policy[p] {
    contact := security_contacts[_]
    is_valid_configuration(contact)
    p = fugue.allow_resource(contact)
}

# Deny with appropriate message if requirements are not met
policy[p] {
    contact := security_contacts[_]
    not is_valid_configuration(contact)
    message := get_violation_message(contact)
    p = fugue.deny_resource_with_message(contact, message)
}

# Helper to get appropriate violation message
get_violation_message(contact) = msg {
    contact.email == ""
    msg = "Security contact email must be configured"
} else = msg {
    not contact.alert_notifications
    msg = "Alert notifications must be enabled for security contacts"
} else = msg {
    not contact.alerts_to_admins
    msg = "Alerts to admins must be enabled for security contacts"
} else = "Invalid security center contact configuration"

# Deny if no security center contact exists
policy[p] {
    count(security_contacts) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_contact", "No security center contact found - security contact email must be configured")
}