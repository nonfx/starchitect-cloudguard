package rules.aws_cloudformation_stack_notification_check

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "CloudFormation.1",
	"title": "CloudFormation stacks should be integrated with Simple Notification Service (SNS)",
	"description": "This control checks whether an Amazon Simple Notification Service notification is integrated with an AWS CloudFormation stack. The control fails for a CloudFormation stack if no SNS notification is associated with it.Configuring an SNS notification with your CloudFormation stack helps immediately notify stakeholders of any events or changes occurring with the stack",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFormation.1"]},
		"severity": "Low",
	},
}

resource_type := "MULTIPLE"

stacks := fugue.resources("aws_cloudformation_stack")

has_notification(stack) {
	count(stack.notification_arns) > 0
}

policy[p] {
	stack := stacks[_]
	has_notification(stack)
	p = fugue.allow_resource(stack)
}

policy[p] {
	stack := stacks[_]
	not has_notification(stack)
	p = fugue.deny_resource_with_message(stack, "CloudFormation stack does not have an SNS notification associated with it")
}
