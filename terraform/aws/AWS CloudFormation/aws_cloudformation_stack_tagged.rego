package rules.aws_cloudformation_stack_tagged

import data.fugue

__rego__metadoc__ := {
	"id": "CloudFormation.2",
	"title": "CloudFormation stacks should be tagged",
	"description": "This control checks whether an AWS CloudFormation stack has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the stack doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the stack isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudFormation.2"]},
		"severity": "Low",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

stacks := fugue.resources("aws_cloudformation_stack")

has_tags(stack) {
	count(stack.tags) > 0
}

policy[p] {
	stack := stacks[_]
	has_tags(stack)
	p = fugue.allow_resource(stack)
}

policy[p] {
	stack := stacks[_]
	not has_tags(stack)
	p = fugue.deny_resource_with_message(stack, "CloudFormation stack does not have any tags")
}
