package rules.ec2_launch_template_public_ip

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.25",
	"title": "Amazon EC2 launch templates should not assign public IPs to network interfaces",
	"description": "This control checks whether EC2 launch templates are configured to assign public IP addresses to network interfaces. Assigning public IPs directly exposes instances to the internet and increases security risks.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.25"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all EC2 launch templates
launch_templates = fugue.resources("aws_launch_template")

# Check if network interface assigns public IP
has_public_ip(template) {
	network_interface := template.network_interface[_]
	network_interface.associate_public_ip_address == true
}

has_public_ip(template) {
	template.network_interface_id != null
	template.associate_public_ip_address == true
}

# Allow launch templates that don't assign public IPs
policy[p] {
	template := launch_templates[_]
	not has_public_ip(template)
	p = fugue.allow_resource(template)
}

# Deny launch templates that assign public IPs
policy[p] {
	template := launch_templates[_]
	has_public_ip(template)
	p = fugue.deny_resource_with_message(template, "EC2 launch template should not assign public IP addresses to network interfaces")
}
