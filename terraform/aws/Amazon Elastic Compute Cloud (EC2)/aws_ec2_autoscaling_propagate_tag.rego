package rules.aws_ec2_autoscaling_propagate_tag

import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "2.14",
	"title": "Ensure EC2 Auto Scaling Groups Propagate Tags to EC2 Instances that it launches",
	"description": "Tags can help with managing, identifying, organizing, searching for, and filtering resources. Additionally, tags can help with security and compliance. Tags can be propagated from an Auto Scaling group to the EC2 instances that it launches.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.14"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

scaling_groups := fugue.resources("aws_autoscaling_group")

# Check if Auto Scaling Group propagates tags to EC2 instances
propagate_tags_enabled(scaling_group) {
	tag := scaling_group.tag[_]
	tag.propagate_at_launch == true
}

group_valid(scaling_group) {
	propagate_tags_enabled(scaling_group)
}

policy[p] {
	scaling_group := scaling_groups[_]
	group_valid(scaling_group)
	p := fugue.allow_resource(scaling_group)
}

policy[p] {
	scaling_group := scaling_groups[_]
	not group_valid(scaling_group)
	p := fugue.deny_resource(scaling_group)
}
