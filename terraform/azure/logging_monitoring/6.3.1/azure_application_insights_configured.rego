package rules.azure_application_insights_configured

import data.fugue

__rego__metadoc__ := {
    "id": "6.3.1",
    "title": "Ensure Application Insights are Configured",
    "description": "Application Insights within Azure act as an Application Performance Monitoring solution providing valuable data into how well an application performs and additional information when performing incident response.",
    "custom": {"controls":{"CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0":["CIS_Microsoft_Azure_Foundations_Benchmark_v3.0.0_6.3.1"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

app_insights = fugue.resources("azurerm_application_insights")

valid_retention_days = {30, 60, 90, 120, 180, 270, 365, 550, 730}

valid_app_types = {"ios", "java", "MobileCenter", "Node.JS", "other", "phone", "store", "web"}

is_properly_configured(insights) {
    insights.workspace_id != null
    insights.retention_in_days > 0
    valid_retention_days[insights.retention_in_days]
    insights.application_type != ""
    valid_app_types[insights.application_type]
}

policy[p] {
    count(app_insights) > 0
    insights := app_insights[_]
    is_properly_configured(insights)
    p = fugue.allow_resource(insights)
}

policy[p] {
    count(app_insights) == 0
    p = fugue.missing_resource_with_message(
        "azurerm_application_insights",
        "No Application Insights found - Application monitoring must be configured"
    )
}

policy[p] {
    insights := app_insights[_]
    not is_properly_configured(insights)
    p = fugue.deny_resource_with_message(
        insights,
        "Application Insights must be configured with workspace ID, valid retention period, and valid application type"
    )
}