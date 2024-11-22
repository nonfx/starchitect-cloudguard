package rules.apigateway_xray_tracing_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "APIGateway.3",
	"title": "API Gateway REST API stages should have AWS X-Ray tracing enabled",
	"description": "This control checks whether AWS X-Ray active tracing is enabled for your Amazon API Gateway REST API stages. X-Ray active tracing enables a more rapid response to performance changes in the underlying infrastructure. Changes in performance could result in a lack of availability of the API. X-Ray active tracing provides real-time metrics of user requests that flow through your API Gateway REST API operations and connected services.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

api_gateway_rest_apis = fugue.resources("aws_api_gateway_rest_api")

api_gateway_stages = fugue.resources("aws_api_gateway_stage")

xray_tracing_enabled(stage, api_gateway_rest_api) {
	stage.rest_api_id == api_gateway_rest_api.id
	stage.xray_tracing_enabled == true
}

policy[p] {
	api_gateway_rest_api = api_gateway_rest_apis[_]
	stage := api_gateway_stages[_]
	not xray_tracing_enabled(stage, api_gateway_rest_api)
	msg := sprintf("AWS X-Ray tracing is not enabled for API Gateway REST API stage '%s'.", [stage.stage_name])
	p = fugue.deny_resource_with_message(stage, msg)
}

policy[p] {
	api_gateway_rest_api = api_gateway_rest_apis[_]
	stage := api_gateway_stages[_]
	xray_tracing_enabled(stage, api_gateway_rest_api)
	p = fugue.allow_resource(stage)
}
