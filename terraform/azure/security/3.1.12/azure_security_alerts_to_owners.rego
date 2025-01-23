package rules.azure_security_alerts_to_owners

import data.fugue

__rego__metadoc__ := {
    "id": "3.1.12",
    "title": "Ensure That 'All users with the following roles' is set to 'Owner'",
    "description": "Enable security alert emails to subscription owners to ensure timely notification of potential security risks.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_3.1.12"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all security center contact resources
security_contacts = fugue.resources("azurerm_security_center_contact")

# Helper to check if alerts to owner is enabled
is_alerts_to_owner_enabled(contact) {
    contact.alerts_to_admins == true
}

# Allow if alerts to owner is enabled
policy[p] {
    contact := security_contacts[_]
    is_alerts_to_owner_enabled(contact)
    p = fugue.allow_resource(contact)
}

# Deny if alerts to owner is disabled
policy[p] {
    contact := security_contacts[_]
    not is_alerts_to_owner_enabled(contact)
    p = fugue.deny_resource_with_message(contact, "Security alerts must be enabled for subscription owners")
}

# Deny if no security center contact exists
policy[p] {
    count(security_contacts) == 0
    p = fugue.missing_resource_with_message("azurerm_security_center_contact", "No security center contact found - security alerts must be configured for subscription owners")
}