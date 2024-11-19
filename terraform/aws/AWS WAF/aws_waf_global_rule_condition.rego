package rules.waf_global_rule_condition

import data.fugue

__rego__metadoc__ := {
	"id": "WAF.6",
	"title": "AWS WAF Classic global rules should have at least one condition",
	"description": "AWS WAF Classic global rules must contain at least one condition to ensure proper traffic inspection and control. Rules without conditions allow traffic to pass without inspection, which may create security vulnerabilities.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.6"]}, "author": "llmagent"},
}

resource_type := "MULTIPLE"

# Get all WAF global rules
waf_rules = fugue.resources("aws_waf_rule")

# Helper to check if rule has predicates
has_predicates(rule) {
	count(rule.predicates) > 0
}

# Allow rules with predicates
policy[p] {
	rule := waf_rules[_]
	has_predicates(rule)
	p = fugue.allow_resource(rule)
}

# Deny rules without predicates
policy[p] {
	rule := waf_rules[_]
	not has_predicates(rule)
	p = fugue.deny_resource_with_message(rule, "WAF global rule does not have any conditions configured, which allows traffic to pass without inspection")
}
