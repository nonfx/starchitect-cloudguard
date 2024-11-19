package rules.apigateway_route_authorization

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "APIGateway.8",
	"title": "API Gateway routes should specify an authorization type",
	"description": "This control checks if Amazon API Gateway routes have an authorization type. The control fails if the API Gateway route doesn't have any authorization type.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.8"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

apigateway_routes = fugue.resources("aws_apigatewayv2_route")

apigatewayv2_apis = fugue.resources("aws_apigatewayv2_api")

valid_custom_values = ["AWS_IAM", "CUSTOM", "JWT"]

has_authorization(route, apigatewayv2_api) {
	route.api_id == apigatewayv2_api.id
	route.authorization_type == valid_custom_values[_]
}

policy[p] {
	apigatewayv2_api = apigatewayv2_apis[_]
	route := apigateway_routes[_]
	has_authorization(route, apigatewayv2_api)
	p = fugue.allow_resource(route)
}

policy[p] {
	apigatewayv2_api = apigatewayv2_apis[_]
	route := apigateway_routes[_]
	not has_authorization(route, apigatewayv2_api)
	msg = sprintf("API Gateway %s route does not specify an authorization type %s", [apigatewayv2_api.name, route.id])
	p = fugue.deny_resource_with_message(route, msg)
}
