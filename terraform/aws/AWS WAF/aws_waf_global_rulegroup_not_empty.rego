package rules.aws_waf_global_rulegroup_not_empty

import data.fugue

__rego__metadoc__ := {
	"id": "WAF.7",
	"title": "AWS WAF Classic global rule groups should have at least one rule",
	"description": "This control checks whether an AWS WAF global rule group has at least one rule. The control fails if no rules are present within a rule group. A WAF global rule group can contain multiple rules. The rule's conditions allow for traffic inspection and take a defined action (allow, block, or count). Without any rules, the traffic passes without inspection. A WAF global rule group with no rules, but with a name or tag suggesting allow, block, or count, could lead to the wrong assumption that one of those actions is occurring.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.7"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

waf_rule_groups := fugue.resources("aws_waf_rule_group")

rule_group_has_rules(group) {
	count(group.activated_rule) > 0
}

policy[p] {
	group := waf_rule_groups[_]
	rule_group_has_rules(group)
	p = fugue.allow_resource(group)
}

policy[p] {
	group := waf_rule_groups[_]
	not rule_group_has_rules(group)
	msg := sprintf("WAF Classic global rule group '%s' does not have any rules", [group.name])
	p = fugue.deny_resource_with_message(group, msg)
}
