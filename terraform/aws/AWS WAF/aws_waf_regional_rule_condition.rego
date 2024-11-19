package rules.waf_regional_rule_condition

import data.fugue

__rego__metadoc__ := {
	"id": "WAF.2",
	"title": "AWS WAF Classic Regional rules should have at least one condition",
	"description": "AWS WAF Classic Regional rules must contain at least one condition to ensure proper traffic inspection and control. Rules without conditions allow all traffic to pass without inspection, potentially creating security vulnerabilities.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.2"]}, "severity": "Medium", "author": "llmagent"},
}

resource_type := "MULTIPLE"

waf_rules = fugue.resources("aws_wafregional_rule")

# Helper to check if rule has predicates
has_predicates(rule) {
	count(rule.predicate) > 0
}

# Allow if rule has at least one predicate
policy[p] {
	rule := waf_rules[_]
	has_predicates(rule)
	p = fugue.allow_resource(rule)
}

# Deny if rule has no predicates
policy[p] {
	rule := waf_rules[_]
	not has_predicates(rule)
	p = fugue.deny_resource_with_message(rule, "WAF Regional rule must have at least one condition configured")
}
