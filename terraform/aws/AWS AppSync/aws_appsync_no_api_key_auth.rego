package rules.aws_appsync_no_api_key_auth

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "AppSync.5",
	"title": "AWS AppSync GraphQL APIs should not be authenticated with API keys",
	"description": "This control checks whether your application uses an API key to interact with an AWS AppSync GraphQL API. The control fails if an AWS AppSync GraphQL API is authenticated with an API key.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_AppSync.5"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

appsync_apis = fugue.resources("aws_appsync_graphql_api")

# Helper function to check if API key authentication is used
api_key_auth_used(api) {
	api.authentication_type == "API_KEY"
}

# Policy rule that creates a set of judgements
policy[p] {
	api := appsync_apis[_]
	not api_key_auth_used(api)
	p = fugue.allow_resource(api)
}

policy[p] {
	api := appsync_apis[_]
	api_key_auth_used(api)
	p = fugue.deny_resource_with_message(api, "AWS AppSync GraphQL API is authenticated with an API key, which is not recommended.")
}
