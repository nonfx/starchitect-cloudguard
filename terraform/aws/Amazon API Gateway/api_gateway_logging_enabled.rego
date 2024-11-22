package rules.api_gateway_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "APIGateway.1",
	"title": "API Gateway REST and WebSocket API execution logging should be enabled",
	"description": "This control checks whether all stages of an Amazon API Gateway REST or WebSocket API have logging enabled. The control fails if the loggingLevel isn't ERROR or INFO for all stages of the API. Unless you provide custom parameter values to indicate that a specific log type should be enabled, Security Hub produces a passed finding if the logging level is either ERROR or INFO.API Gateway REST or WebSocket API stages should have relevant logs enabled. API Gateway REST and WebSocket API execution logging provides detailed records of requests made to API Gateway REST and WebSocket API stages. The stages include API integration backend responses, Lambda authorizer responses, and the requestId for AWS integration endpoints",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.1"]}, "author": "Starchitect Agent", "severity": "Medium"},
}

resource_type := "MULTIPLE"

api_gateway_rest_apis = fugue.resources("aws_api_gateway_rest_api")

api_gateway_stages = fugue.resources("aws_api_gateway_stage")

api_gateway_method_settings = fugue.resources("aws_api_gateway_method_settings")

valid_logging_levels = ["INFO", "ERROR"]

has_valid_logging_level(stage, api_gateway_rest_api) {
	stage.rest_api_id == api_gateway_rest_api.id
	stage.access_log_settings[0]
	stage.access_log_settings[0].format != ""
	stage.access_log_settings[0].destination_arn != ""
}

has_valid_method_settings(method_settings, api_gateway_rest_api) {
	method_settings.rest_api_id == api_gateway_rest_api.id
	method_settings.settings[_].logging_level == valid_logging_levels[_]
}

policy[p] {
	api_gateway_rest_api = api_gateway_rest_apis[_]
	stage = api_gateway_stages[_]
	has_valid_logging_level(stage, api_gateway_rest_api)
	p = fugue.allow_resource(api_gateway_rest_api)
}

policy[p] {
	api_gateway_rest_api = api_gateway_rest_apis[_]
	stage = api_gateway_stages[_]
	not has_valid_logging_level(stage, api_gateway_rest_api)
	msg = sprintf("API Gateway stage %s does not have logging enabled with a valid logging level (INFO or ERROR)", [stage])
	p = fugue.deny_resource_with_message(stage, msg)
}

policy[p] {
	api_gateway_rest_api = api_gateway_rest_apis[_]
	method_settings = api_gateway_method_settings[_]
	has_valid_method_settings(method_settings, api_gateway_rest_api)
	p = fugue.allow_resource(api_gateway_rest_api)
}

policy[p] {
	api_gateway_rest_api = api_gateway_rest_apis[_]
	method_settings = api_gateway_method_settings[_]
	not has_valid_method_settings(method_settings, api_gateway_rest_api)
	p = fugue.deny_resource_with_message(api_gateway_rest_api, "API Gateway method settings do not have a valid logging level (INFO or ERROR)")
}
