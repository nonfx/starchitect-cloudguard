package rules.aws_autoscaling_launch_template

import data.fugue

__rego__metadoc__ := {
	"id": "AutoScaling.9",
	"title": "Amazon EC2 Auto Scaling groups should use Amazon EC2 launch templates",
	"description": "EC2 Auto Scaling groups must use launch templates instead of launch configurations for better access to latest features.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_AutoScaling.9"]}, "severity": "Medium", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

asg_resources = fugue.resources("aws_autoscaling_group")

# Helper function to check if ASG uses launch template
uses_launch_template(asg) {
	asg.launch_template[_].id != null
}

# Helper function to check if ASG uses mixed instances policy with launch template
uses_mixed_instances_template(asg) {
	asg.mixed_instances_policy[_].launch_template[_].launch_template_specification[_].launch_template_id != null
}

policy[p] {
	asg := asg_resources[_]
	uses_launch_template(asg)
	p = fugue.allow_resource(asg)
}

policy[p] {
	asg := asg_resources[_]
	uses_mixed_instances_template(asg)
	p = fugue.allow_resource(asg)
}

policy[p] {
	asg := asg_resources[_]
	not uses_launch_template(asg)
	not uses_mixed_instances_template(asg)
	p = fugue.deny_resource_with_message(asg, "Auto Scaling group must use launch template instead of launch configuration")
}
