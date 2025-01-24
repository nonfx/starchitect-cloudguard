package rules.azure_app_service_remote_debugging

import data.fugue

__rego__metadoc__ := {
    "id": "9.12",
    "title": "Ensure that 'Remote debugging' is set to 'Off'",
    "description": "Remote Debugging allows Azure App Service to be debugged in real-time directly on the Azure environment.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_9.12"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

app_services = fugue.resources("azurerm_app_service")

# Helper to check if remote debugging is disabled
is_remote_debugging_disabled(app) {
    app.site_config[_].remote_debugging_enabled == false
}

# Allow if remote debugging is disabled
policy[p] {
    app := app_services[_]
    is_remote_debugging_disabled(app)
    p = fugue.allow_resource(app)
}

# Deny if remote debugging is enabled
policy[p] {
    app := app_services[_]
    not is_remote_debugging_disabled(app)
    p = fugue.deny_resource_with_message(app, "Remote debugging must be disabled for enhanced security")
}