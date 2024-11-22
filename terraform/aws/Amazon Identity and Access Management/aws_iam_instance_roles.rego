package rules.aws_iam_instance_roles

import data.fugue

__rego__metadoc__ := {
	"id": "1.18",
	"title": "Ensure IAM instance roles are used for AWS resource access from instances",
	"description": "AWS access from within AWS instances can be done by either encoding AWS keys into AWS API calls or by assigning the instance to a role which has an appropriate permissions policy for the required access. AWS Access means accessing the APIs of AWS in order to access AWS resources or manage AWS account resources.",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_1.18"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

instances := fugue.resources("aws_instance")

instance_has_iam_role(instance) {
	instance.iam_instance_profile != null
}

policy[p] {
	instance := instances[_]
	instance_has_iam_role(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := instances[_]
	not instance_has_iam_role(instance)
	msg := sprintf("Instance '%s' does not have an IAM instance role assigned.", [instance.id])
	p = fugue.deny_resource_with_message(instance, msg)
}
