package rules.ec2_subnet_auto_assign_public_ip

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.15",
	"title": "Amazon EC2 subnets should not automatically assign public IP addresses",
	"description": "This control checks if EC2 subnets are configured to automatically assign public IP addresses. The control fails if the subnet's MapPublicIpOnLaunch attribute is set to true.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.15"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all EC2 subnets
subnets = fugue.resources("aws_subnet")

# Helper to check if subnet auto-assigns public IPs
is_public_ip_on_launch(subnet) {
	subnet.map_public_ip_on_launch == true
}

# Policy rule for subnets
policy[p] {
	subnet := subnets[_]
	not is_public_ip_on_launch(subnet)
	p = fugue.allow_resource(subnet)
}

policy[p] {
	subnet := subnets[_]
	is_public_ip_on_launch(subnet)
	p = fugue.deny_resource_with_message(subnet, "EC2 subnet should not automatically assign public IP addresses")
}
