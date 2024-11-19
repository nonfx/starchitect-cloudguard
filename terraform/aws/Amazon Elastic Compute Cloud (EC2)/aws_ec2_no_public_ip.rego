package rules.ec2_no_public_ip

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.9",
	"title": "Amazon EC2 instances should not have a public IPv4 address",
	"description": "This control checks whether EC2 instances have a public IPv4 address. The control fails if an EC2 instance has a public IP address configured.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.9"]}, "severity": "High", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

# Get all EC2 instances
ec2_instances = fugue.resources("aws_instance")

# Helper to check if instance has public IP
has_public_ip(instance) {
	instance.associate_public_ip_address == true
}

has_public_ip(instance) {
	instance.network_interface[_].associate_public_ip_address == true
}

# Policy rule for EC2 instances
policy[p] {
	instance := ec2_instances[_]
	not has_public_ip(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := ec2_instances[_]
	has_public_ip(instance)
	p = fugue.deny_resource_with_message(instance, "EC2 instance should not have a public IPv4 address")
}
