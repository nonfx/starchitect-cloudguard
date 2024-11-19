package rules.aws_appsync_field_level_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "AppSync.2",
	"title": "AWS AppSync should have field-level logging enabled",
	"description": "This control checks whether an AWS AppSync API has field-level logging turned on. The control fails if the field resolver log level is set to None. Security Hub produces a passed finding if the field resolver log level is either ERROR or ALL. Logging and metrics help identify, troubleshoot, and optimize GraphQL queries.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_AppSync.2"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

appsync_apis = fugue.resources("aws_appsync_graphql_api")

# Helper function to check if logging is enabled
logging_enabled(api) {
	api.log_config[_].field_log_level != "NONE"
}

# Policy rule that creates a set of judgements
policy[p] {
	api := appsync_apis[_]
	logging_enabled(api)
	p = fugue.allow_resource(api)
}

policy[p] {
	api := appsync_apis[_]
	not logging_enabled(api)
	p = fugue.deny_resource_with_message(api, "AWS AppSync API does not have field-level logging enabled.")
}
