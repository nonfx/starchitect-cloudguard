package rules.ec2_multiple_eni

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.17",
	"title": "Amazon EC2 instances should not use multiple ENIs",
	"description": "This control checks if EC2 instances use multiple Elastic Network Interfaces (ENIs). The control fails if an instance has more than one ENI attached.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.17"]}, "severity": "Low"},
}

resource_type := "MULTIPLE"

# Get all EC2 instances and network interfaces
ec2_instances = fugue.resources("aws_instance")

network_interfaces = fugue.resources("aws_network_interface_attachment")

# Helper to count ENIs attached to an instance
count_enis(instance_id) = total {
	attachments := {x |
		attachment := network_interfaces[_]
		attachment.instance_id == instance_id
		x = attachment
	}
	total := count(attachments)
}

# Policy for EC2 instances
policy[p] {
	instance := ec2_instances[_]
	eni_count := count_enis(instance.id)
	eni_count <= 1
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := ec2_instances[_]
	eni_count := count_enis(instance.id)
	eni_count > 1
	p = fugue.deny_resource_with_message(instance, sprintf("EC2 instance has %v ENIs attached. Instances should use only one ENI to reduce network complexity", [eni_count]))
}
