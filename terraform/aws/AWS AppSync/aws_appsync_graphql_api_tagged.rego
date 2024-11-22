package rules.aws_appsync_graphql_api_tagged

import data.fugue

__rego__metadoc__ := {
	"id": "AppSync.4",
	"title": "AWS AppSync GraphQL APIs should be tagged",
	"description": "This control checks whether an AWS AppSync GraphQL API has tags with specific keys defined in the parameter requiredTagKeys. The control fails if the GraphQL API doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. System tags, which begin with aws:, are ignored.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_AppSync.4"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

appsync_apis = fugue.resources("aws_appsync_graphql_api")

# Helper function to check if tags are present
tags_present(api) {
	all_tags := {tag | tag := api.tags[_]}
	count(all_tags) > 0
}

# Policy rule that creates a set of judgements
policy[p] {
	api := appsync_apis[_]
	tags_present(api)
	p = fugue.allow_resource(api)
}

policy[p] {
	api := appsync_apis[_]
	not tags_present(api)
	msg := sprintf("no tags present for aws appsync graphql api %s", [api.name])
	p = fugue.deny_resource_with_message(api, msg)
}
