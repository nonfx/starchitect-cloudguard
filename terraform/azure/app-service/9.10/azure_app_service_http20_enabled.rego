package rules.azure_app_service_http20_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "9.10",
    "title": "Ensure that 'HTTP20enabled' is set to 'true'",
    "description": "Periodically, newer versions are released for HTTP either due to security flaws or to include additional functionality.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_9.10"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

app_services = fugue.resources("azurerm_app_service")

# Helper to check if HTTP 2.0 is enabled
is_http20_enabled(app) {
    app.site_config[_].http2_enabled == true
}

# Allow if HTTP 2.0 is enabled
policy[p] {
    app := app_services[_]
    is_http20_enabled(app)
    p = fugue.allow_resource(app)
}

# Deny if HTTP 2.0 is not enabled
policy[p] {
    app := app_services[_]
    not is_http20_enabled(app)
    p = fugue.deny_resource_with_message(app, "HTTP 2.0 should be enabled for enhanced security and performance")
}