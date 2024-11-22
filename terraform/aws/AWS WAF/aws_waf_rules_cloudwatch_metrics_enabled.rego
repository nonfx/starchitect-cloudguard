package rules.aws_waf_rules_cloudwatch_metrics_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "WAF.12",
	"title": "AWS WAF rules should have CloudWatch metrics enabled",
	"description": "This control checks whether an AWS WAF rule or rule group has Amazon CloudWatch metrics enabled. The control fails if the rule or rule group doesn't have CloudWatch metrics enabled.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.12"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

waf_rule_groups := fugue.resources("aws_wafv2_rule_group")

waf_web_acls := fugue.resources("aws_wafv2_web_acl")

has_cloudwatch_metrics_enabled(resource) {
	resource.visibility_config[_].cloudwatch_metrics_enabled == true
}

policy[p] {
	resource := waf_rule_groups[_]
	has_cloudwatch_metrics_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := waf_rule_groups[_]
	not has_cloudwatch_metrics_enabled(resource)
	msg := sprintf("WAF rule group '%s' does not have CloudWatch metrics enabled", [resource.name])
	p = fugue.deny_resource_with_message(resource, msg)
}

policy[p] {
	resource := waf_web_acls[_]
	has_cloudwatch_metrics_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := waf_web_acls[_]
	not has_cloudwatch_metrics_enabled(resource)
	msg := sprintf("WAF web ACL '%s' does not have CloudWatch metrics enabled", [resource.name])
	p = fugue.deny_resource_with_message(resource, msg)
}
