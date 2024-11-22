package rules.aws_ebs_delete_on_termination

import data.fugue

__rego__metadoc__ := {
	"id": "2.12",
	"title": "Ensure EBS volumes attached to an EC2 instance is marked for deletion upon instance termination",
	"description": "This rule ensures that Amazon Elastic Block Store volumes that are attached to Amazon Elastic Compute Cloud (Amazon EC2) instances are marked for deletion when an instance is terminated. If an Amazon EBS volume isn’t deleted when the instance that it’s attached to is terminated, it may violate the concept of least functionality.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.12"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

instances = fugue.resources("aws_instance")

instance_has_delete_on_termination(instance) {
	some i
	block_device := instance.root_block_device[i]
	block_device.delete_on_termination == true
}

instance_has_delete_on_termination(instance) {
	some i
	block_device := instance.ebs_block_device[i]
	block_device.delete_on_termination == true
}

policy[p] {
	instance := instances[_]
	instance_has_delete_on_termination(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := instances[_]
	not instance_has_delete_on_termination(instance)
	p = fugue.deny_resource_with_message(instance, "EC2 instance does not have delete_on_termination set to true for its EBS volumes")
}
