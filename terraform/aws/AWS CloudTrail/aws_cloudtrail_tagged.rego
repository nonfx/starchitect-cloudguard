package rules.aws_cloudtrail_tagged

import data.fugue

__rego__metadoc__ := {
	"author": "ankit@nonfx.com",
	"id": "CloudTrail.9",
	"title": "CloudTrail trails should be tagged",
	"description": "This control checks whether an AWS CloudTrail trail has tags with the specific keys defined in the parameter requiredTagKeys. The control fails if the trail doesn’t have any tag keys or if it doesn’t have all the keys specified in the parameter requiredTagKeys. If the parameter requiredTagKeys isn't provided, the control only checks for the existence of a tag key and fails if the trail isn't tagged with any key. System tags, which are automatically applied and begin with aws:, are ignored. A tag is a label that you assign to an AWS resource, and it consists of a key and an optional value. You can create tags to categorize resources by purpose, owner, environment, or other criteria. Tags can help you identify, organize, search for, and filter resources. Tagging also helps you track accountable resource owners for actions and notifications. When you use tagging, you can implement attribute-based access control (ABAC) as an authorization strategy, which defines permissions based on tags. You can attach tags to IAM entities (users or roles) and to AWS resources. You can create a single ABAC policy or a separate set of policies for your IAM principals. You can design these ABAC policies to allow operations when the principal's tag matches the resource tag",
	"custom": {
		"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.9"]},
		"severity": "Low",
	},
}

resource_type := "MULTIPLE"

trails := fugue.resources("aws_cloudtrail")

has_tags(trail) {
	count(trail.tags) > 0
}

policy[p] {
	trail := trails[_]
	has_tags(trail)
	p := fugue.allow_resource(trail)
}

policy[p] {
	trail := trails[_]
	not has_tags(trail)
	p := fugue.deny_resource_with_message(trail, "CloudTrail trail does not have any tags")
}
