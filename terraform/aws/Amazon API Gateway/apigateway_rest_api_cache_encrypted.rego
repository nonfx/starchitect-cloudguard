package rules.apigateway_rest_api_cache_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "APIGateway.5",
	"title": "API Gateway REST API cache data should be encrypted at rest",
	"description": "This control checks whether all methods in API Gateway REST API stages that have cache enabled are encrypted. The control fails if any method in an API Gateway REST API stage is configured to cache and the cache is not encrypted.",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.5"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

api_gateway_stages = fugue.resources("aws_api_gateway_stage")

api_gateway_method_settings = fugue.resources("aws_api_gateway_method_settings")

is_cache_enabled(stage) {
	stage.cache_cluster_enabled == true
	stage.cache_cluster_size > 0
}

is_cache_encrypted(method_settings) {
	method_settings.settings[0].cache_data_encrypted == true
}

policy[p] {
	stage := api_gateway_stages[_]
	is_cache_enabled(stage)
	method_settings := api_gateway_method_settings[_]
	method_settings.rest_api_id == stage.rest_api_id
	method_settings.stage_name == stage.stage_name
	is_cache_encrypted(method_settings)
	p = fugue.allow_resource(stage)
}

policy[p] {
	stage := api_gateway_stages[_]
	not is_cache_enabled(stage)
	msg := sprintf("API Gateway stage does not have caching enabled [%s]", [stage.id])
	p = fugue.deny_resource_with_message(stage, msg)
}

policy[p] {
	stage := api_gateway_stages[_]
	is_cache_enabled(stage)
	method_settings := api_gateway_method_settings[_]
	method_settings.rest_api_id == stage.rest_api_id
	method_settings.stage_name == stage.stage_name
	not is_cache_encrypted(method_settings)
	msg := sprintf("API Gateway stage has caching enabled but the cache is not encrypted [%s]", [method_settings])
	p = fugue.deny_resource_with_message(method_settings, msg)
}
