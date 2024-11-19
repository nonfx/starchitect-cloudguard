package rules.waf_regional_rule_group_not_empty

import data.fugue

__rego__metadoc__ := {
	"id": "WAF.3",
	"title": "AWS WAF Classic Regional rule groups should have at least one rule",
	"description": "This control checks if AWS WAF Regional rule groups contain at least one rule. Rule groups without rules allow traffic to pass without inspection, potentially creating security vulnerabilities.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.3"]}, "severity": "Medium", "author": "llmagent"},
}

resource_type := "MULTIPLE"

# Get all WAF Regional rule groups
waf_rule_groups = fugue.resources("aws_wafregional_rule_group")

# Helper function to check if rule group has rules
has_rules(group) {
	count(group.activated_rule) > 0
}

# Allow rule groups with at least one rule
policy[p] {
	group := waf_rule_groups[_]
	has_rules(group)
	p = fugue.allow_resource(group)
}

# Deny rule groups without rules
policy[p] {
	group := waf_rule_groups[_]
	not has_rules(group)
	p = fugue.deny_resource_with_message(group, "WAF Regional rule group does not contain any rules, which allows traffic to pass without inspection")
}
