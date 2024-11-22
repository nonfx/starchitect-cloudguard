package rules.aws_wafv2_webacl_rule_not_empty

import data.fugue

__rego__metadoc__ := {
	"id": "WAF.10",
	"title": "AWS WAF web ACLs should have at least one rule or rule group",
	"description": "This control checks whether an AWS WAFV2 web access control list (web ACL) contains at least one rule or rule group. The control fails if a web ACL does not contain any rules or rule groups. A web ACL gives you fine-grained control over all of the HTTP(S) web requests that your protected resource responds to. A web ACL should contain a collection of rules and rule groups that inspect and control web requests. If a web ACL is empty, the web traffic can pass without being detected or acted upon by AWS WAF depending on the default action.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.10"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

web_acls := fugue.resources("aws_wafv2_web_acl")

has_rules(web_acl) {
	count(web_acl.rule) > 0
}

policy[p] {
	web_acl := web_acls[_]
	has_rules(web_acl)
	p = fugue.allow_resource(web_acl)
}

policy[p] {
	web_acl := web_acls[_]
	not has_rules(web_acl)
	p = fugue.deny_resource_with_message(web_acl, "WAF web ACL does not contain any rules or rule groups")
}
