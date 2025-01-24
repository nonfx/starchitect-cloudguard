package rules.azure_webapp_tls_version

import data.fugue

__rego__metadoc__ := {
    "id": "9.4",
    "title": "Ensure Web App is using the latest version of TLS encryption",
    "description": "The TLS protocol secures transmission of data over the internet using standard encryption technology.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_9.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all App Service resources
app_services = fugue.resources("azurerm_app_service")

# Helper to check if TLS version is 1.2
is_tls_compliant(app) {
    app.site_config[_].min_tls_version == "1.2"
}

# Allow if TLS version is 1.2
policy[p] {
    app := app_services[_]
    is_tls_compliant(app)
    p = fugue.allow_resource(app)
}

# Deny if TLS version is not 1.2
policy[p] {
    app := app_services[_]
    not is_tls_compliant(app)
    p = fugue.deny_resource_with_message(app, "Web App must use TLS version 1.2 for secure data transmission")
}