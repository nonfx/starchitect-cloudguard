package rules.aws_waf_global_webacl_not_empty

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "WAF.8",
	"title": "AWS WAF Classic global web ACLs should have at least one rule or rule group",
	"description": "This control checks whether an AWS WAF global web ACL contains at least one WAF rule or WAF rule group. The control fails if a web ACL does not contain any WAF rules or rule groups. A WAF global web ACL can contain a collection of rules and rule groups that inspect and control web requests. If a web ACL is empty, the web traffic can pass without being detected or acted upon by WAF depending on the default action.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.8"]}},
}

resource_type := "MULTIPLE"

waf_webacls := fugue.resources("aws_waf_web_acl")

has_rules_or_groups(webacl) {
	count(webacl.rules) > 0
}

policy[p] {
	webacl := waf_webacls[_]
	has_rules_or_groups(webacl)
	p = fugue.allow_resource(webacl)
}

policy[p] {
	webacl := waf_webacls[_]
	not has_rules_or_groups(webacl)
	msg := sprintf("WAF Classic global web ACL '%s' does not have any rules or rule groups", [webacl.name])
	p = fugue.deny_resource_with_message(webacl, msg)
}
