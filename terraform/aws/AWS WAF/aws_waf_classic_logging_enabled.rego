package rules.waf_classic_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "WAF.1",
	"title": "AWS WAF Classic Global Web ACL logging should be enabled",
	"description": "This control checks whether logging is enabled for an AWS WAF global web ACL. Logging is crucial for monitoring web traffic, maintaining security compliance, and meeting business requirements.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_WAF.1"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all WAF Classic Web ACLs and logging configurations
waf_acls = fugue.resources("aws_waf_web_acl")

waf_logging_configs = fugue.resources("aws_waf_web_acl_logging_configuration")

# Helper function to check if logging is enabled for a WAF ACL
has_logging(acl) {
	config := waf_logging_configs[_]
	config.resource_arn == acl.id
	config.log_destination != null
}

# Allow if logging is enabled and properly configured
policy[p] {
	acl := waf_acls[_]
	has_logging(acl)
	p = fugue.allow_resource(acl)
}

# Deny if logging is not enabled or improperly configured
policy[p] {
	acl := waf_acls[_]
	not has_logging(acl)
	p = fugue.deny_resource_with_message(acl, "WAF Classic Global Web ACL logging must be enabled with a valid log destination")
}
