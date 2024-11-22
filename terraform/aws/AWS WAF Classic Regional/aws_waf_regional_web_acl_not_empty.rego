package rules.waf_regional_web_acl_not_empty

import data.fugue

__rego__metadoc__ := {
	"id": "WAF.4",
	"title": "AWS WAF Classic Regional web ACLs should have at least one rule or rule group",
	"description": "AWS WAF Classic Regional web ACLs must contain at least one rule or rule group for proper traffic inspection and control.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.4"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all WAF Regional web ACLs
web_acls = fugue.resources("aws_wafregional_web_acl")

# Check if web ACL has rules
has_rules(acl) {
	count(acl.rule) > 0
}

# Check if web ACL has rule groups
has_rule_groups(acl) {
	count(acl.rule_group) > 0
}

# Allow if web ACL has rules or rule groups
policy[p] {
	acl := web_acls[_]
	has_rules(acl)
	p = fugue.allow_resource(acl)
}

policy[p] {
	acl := web_acls[_]
	has_rule_groups(acl)
	p = fugue.allow_resource(acl)
}

# Deny if web ACL has no rules or rule groups
policy[p] {
	acl := web_acls[_]
	not has_rules(acl)
	not has_rule_groups(acl)
	p = fugue.deny_resource_with_message(
		acl,
		sprintf("WAF Regional web ACL '%s' must have at least one rule or rule group", [acl.name]),
	)
}
