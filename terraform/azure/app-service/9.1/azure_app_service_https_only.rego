package rules.azure_app_service_https_only

import data.fugue

__rego__metadoc__ := {
    "id": "9.1",
    "title": "Ensure 'HTTPS Only' is set to 'On'",
    "description": "Azure App Service allows apps to run under both HTTP and HTTPS by default. Apps can be accessed by anyone using non-secure HTTP links by default. HTTPS-only mode should be enabled to redirect all HTTP traffic to HTTPS.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_9.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all App Service resources
app_services = fugue.resources("azurerm_app_service")

# Helper to check if HTTPS Only is enabled
is_https_only(app) {
    app.https_only == true
}

# Allow if HTTPS Only is enabled
policy[p] {
    app := app_services[_]
    is_https_only(app)
    p = fugue.allow_resource(app)
}

# Deny if HTTPS Only is not enabled
policy[p] {
    app := app_services[_]
    not is_https_only(app)
    p = fugue.deny_resource_with_message(app, "App Service must have HTTPS Only enabled to ensure secure communication")
}
