package rules.apigateway_use_ssl_certificates

import data.fugue

__rego__metadoc__ := {
	"id": "APIGateway.2",
	"title": "API Gateway REST API stages should be configured to use SSL certificates for backend authentication",
	"description": "This control checks whether Amazon API Gateway REST API stages have SSL certificates configured. Backend systems use these certificates to authenticate that incoming requests are from API Gateway.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.2"]},
		"severity": "High",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

api_gateway_stages = fugue.resources("aws_api_gateway_stage")

api_gateway_rest_apis = fugue.resources("aws_api_gateway_rest_api")

ssl_certificate_configured(stage, api_gateway_rest_api) {
	api_gateway_rest_api.id == stage.rest_api_id
	stage.client_certificate_id != null
	stage.client_certificate_id != ""
}

policy[p] {
	api_gateway_rest_api = api_gateway_rest_apis[_]
	stage := api_gateway_stages[_]
	not ssl_certificate_configured(stage, api_gateway_rest_api)
	msg := sprintf("API Gateway %s REST API stage '%s' is not configured with an SSL certificate for backend authentication.", [api_gateway_rest_api.id, stage.stage_name])
	p = fugue.deny_resource_with_message(stage, msg)
}

policy[p] {
	api_gateway_rest_api = api_gateway_rest_apis[_]
	stage := api_gateway_stages[_]
	ssl_certificate_configured(stage, api_gateway_rest_api)
	p = fugue.allow_resource(stage)
}
