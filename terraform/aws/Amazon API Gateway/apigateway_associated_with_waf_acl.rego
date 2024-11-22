package rules.apigateway_associated_with_waf_acl

import data.fugue

__rego__metadoc__ := {
	"id": "APIGateway.4",
	"title": "API Gateway should be associated with a WAF Web ACL",
	"description": "This control checks whether an API Gateway stage uses an AWS WAF web access control list (ACL). This control fails if an AWS WAF web ACL is not attached to a REST API Gateway stage. AWS WAF is a web application firewall that helps protect web applications and APIs from attacks. It enables you to configure an ACL, which is a set of rules that allow, block, or count web requests based on customizable web security rules and conditions that you define. Ensure that your API Gateway stage is associated with an AWS WAF web ACL to help protect it from malicious attacks.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_APIGateway.4"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

api_gateway_stages = fugue.resources("aws_api_gateway_stage")

waf_acl_attached(stage) {
	stage.web_acl_arn != null
}

policy[p] {
	stage := api_gateway_stages[_]
	not waf_acl_attached(stage)
	msg := sprintf("AWS WAF web ACL is not attached to API Gateway REST API stage '%s'.", [stage.stage_name])
	p = fugue.deny_resource_with_message(stage, msg)
}

policy[p] {
	stage := api_gateway_stages[_]
	waf_acl_attached(stage)
	p = fugue.allow_resource(stage)
}
