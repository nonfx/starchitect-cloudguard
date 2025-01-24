package rules.azure_app_service_ftps_state

import data.fugue

__rego__metadoc__ := {
    "id": "9.3",
    "title": "Ensure 'FTP State' is set to 'FTPS Only' or 'Disabled'",
    "description": "By default, App Services can be deployed over FTP. If FTP is required for an essential deployment workflow, FTPS should be required for FTP login for all App Services.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_9.3"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

app_services = fugue.resources("azurerm_app_service")

is_valid_ftps_state(app) {
    app.site_config[_].ftps_state == "FtpsOnly"
}

is_valid_ftps_state(app) {
    app.site_config[_].ftps_state == "Disabled"
}

policy[p] {
    app := app_services[_]
    is_valid_ftps_state(app)
    p = fugue.allow_resource(app)
}

policy[p] {
    app := app_services[_]
    not is_valid_ftps_state(app)
    p = fugue.deny_resource_with_message(app, "FTP State must be set to 'FTPS Only' or 'Disabled' for enhanced security")
}