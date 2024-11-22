package rules.aws_securityhub_enabled

import data.fugue

resource_type := "MULTIPLE"

__rego__metadoc__ := {
	"id": "4.16",
	"title": "Ensure AWS Security Hub is enabled",
	"description": "Security Hub collects security data from across AWS accounts, services, and supported third-party partner products and helps you analyze your security trends and identify the highest priority security issues. When you enable Security Hub, it begins to consume, aggregate, organize, and prioritize findings from AWS services that you have enabled, such as Amazon GuardDuty, Amazon Inspector, and Amazon Macie. You can also enable integrations with AWS partner security products.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_4.16"]},"author":"Starchitect Agent"},
}

securityhubs := fugue.resources("aws_securityhub_account")

aws_securityhub_defined(hub) {
	hub != {}
}

policy[p] {
	hub := securityhubs[_]
	aws_securityhub_defined(hub)
	p = fugue.allow_resource(hub)
}

policy[p] {
	hub := securityhubs[_]
	not aws_securityhub_defined(hub)
	msg := "AWS Security Hub account is not defined. Ensure AWS Security Hub is enabled."
	p = fugue.deny_resource_with_message(hub, msg)
}
