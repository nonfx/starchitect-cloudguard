package rules.azure_app_service_auth_enabled

import data.fugue

__rego__metadoc__ := {
    "id": "9.2.b",
    "title": "Ensure App Service Authentication is set up for apps in Azure App Service",
    "description": "Azure App Service Authentication is a feature that can prevent anonymous HTTP requests from reaching a Web Application or authenticate those with tokens before they reach the app.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_9.2.b"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

web_apps = fugue.resources("azurerm_linux_web_app")

is_auth_enabled(app) {
    app.auth_settings_v2[_].auth_enabled == true
    app.auth_settings_v2[_].require_authentication == true
    has_valid_provider(app)
}

has_valid_provider(app) {
    app.auth_settings_v2[_].active_directory_v2[_].client_id != null
    app.auth_settings_v2[_].active_directory_v2[_].client_secret_setting_name != null
    app.auth_settings_v2[_].active_directory_v2[_].tenant_auth_endpoint != null
}

policy[p] {
    app := web_apps[_]
    is_auth_enabled(app)
    p = fugue.allow_resource(app)
}

policy[p] {
    app := web_apps[_]
    not is_auth_enabled(app)
    p = fugue.deny_resource_with_message(
        app,
        "App Service must have authentication enabled and properly configured with a valid identity provider"
    )
}
