package rules.apigateway_v2_access_logging

import data.fugue

__rego__metadoc__ := {
	"id": "APIGateway.9",
	"title": "Access logging should be configured for API Gateway V2 Stages",
	"description": "This control checks if Amazon API Gateway V2 stages have access logging configured. This control fails if access log settings aren't defined.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.9"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

apigatewayv2_apis = fugue.resources("aws_apigatewayv2_api")

apigateway_v2_stages = fugue.resources("aws_apigatewayv2_stage")

has_access_logging(stage, apigatewayv2_api) {
	apigatewayv2_api.id == stage.api_id
	stage.access_log_settings[0].destination_arn != null
	stage.access_log_settings[0].destination_arn != ""
	stage.access_log_settings[0].format != null
	stage.access_log_settings[0].format != ""
}

policy[p] {
	apigatewayv2_api = apigatewayv2_apis[_]
	stage := apigateway_v2_stages[_]
	has_access_logging(stage, apigatewayv2_api)
	p = fugue.allow_resource(stage)
}

policy[p] {
	apigatewayv2_api = apigatewayv2_apis[_]
	stage := apigateway_v2_stages[_]
	not has_access_logging(stage, apigatewayv2_api)
	p = fugue.deny_resource_with_message(stage, "API Gateway V2 stage does not have access logging configured")
}
