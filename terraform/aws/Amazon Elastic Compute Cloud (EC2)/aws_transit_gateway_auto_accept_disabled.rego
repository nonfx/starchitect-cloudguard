package rules.transit_gateway_auto_accept_disabled

import data.fugue

__rego__metadoc__ := {
	"id": "EC2.23",
	"title": "Amazon EC2 Transit Gateways should not automatically accept VPC attachment requests",
	"description": "This control checks if EC2 Transit Gateways are configured to automatically accept VPC attachment requests. The control fails if AutoAcceptSharedAttachments is enabled.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.23"]},"severity":"High","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all transit gateways
transit_gateways = fugue.resources("aws_ec2_transit_gateway")

# Helper to check if auto accept is disabled
is_auto_accept_disabled(gateway) {
	gateway.auto_accept_shared_attachments == "disable"
}

# Allow if auto accept is disabled
policy[p] {
	gateway := transit_gateways[_]
	is_auto_accept_disabled(gateway)
	p = fugue.allow_resource(gateway)
}

# Deny if auto accept is enabled
policy[p] {
	gateway := transit_gateways[_]
	not is_auto_accept_disabled(gateway)
	p = fugue.deny_resource_with_message(gateway, "Transit Gateway should not automatically accept VPC attachment requests. Disable auto-accept shared attachments for better security control.")
}
