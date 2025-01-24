package rules.azure_app_service_managed_identity

import data.fugue

__rego__metadoc__ := {
    "id": "9.5",
    "title": "Ensure that Register with Entra ID is enabled on App Service",
    "description": "Managed service identity in App Service provides more security by eliminating secrets from the app.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_9.5"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

app_services = fugue.resources("azurerm_app_service")

# Helper to check if system-assigned managed identity is enabled
is_managed_identity_enabled(app) {
    app.identity[_].type == "SystemAssigned"
}

# Allow if system-assigned managed identity is enabled
policy[p] {
    app := app_services[_]
    is_managed_identity_enabled(app)
    p = fugue.allow_resource(app)
}

# Deny if system-assigned managed identity is not enabled
policy[p] {
    app := app_services[_]
    not is_managed_identity_enabled(app)
    p = fugue.deny_resource_with_message(app, "App Service must have system-assigned managed identity enabled for secure Azure service connections")
}