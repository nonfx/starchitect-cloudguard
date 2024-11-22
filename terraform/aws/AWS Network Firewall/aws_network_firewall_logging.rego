package rules.network_firewall_logging

import data.fugue

__rego__metadoc__ := {
	"id": "NetworkFirewall.2",
	"title": "Network Firewall logging should be enabled",
	"description": "AWS Network Firewall logging must be enabled to track detailed network traffic information and stateful rule actions.",
	"custom": {"controls":{"AWS-Foundational-Security-Best-Practices_v1.0.0":["AWS-Foundational-Security-Best-Practices_v1.0.0_NetworkFirewall.2"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# Get all Network Firewall and logging configuration resources
firewalls = fugue.resources("aws_networkfirewall_firewall")

logging_configs = fugue.resources("aws_networkfirewall_logging_configuration")

log_values = ["ALERT", "FLOW"]

log_destination_types = ["CloudWatchLogs", "S3", "KinesisDataFirehose"]

# Helper function to check if log destination is valid
is_valid_destination(dest_config) {
	dest_config.log_destination != null
	dest_config.log_type == log_values[_]
	dest_config.log_destination_type == log_destination_types[_]
}

# Helper function to check if firewall has valid logging configuration
has_valid_logging(firewall) {
	config := logging_configs[_]
	dest_config := config.logging_configuration[_].log_destination_config[_]
	is_valid_destination(dest_config)
}

# Allow if firewall has valid logging configuration
policy[p] {
	firewall := firewalls[_]
	has_valid_logging(firewall)
	p = fugue.allow_resource(firewall)
}

# Deny if firewall doesn't have valid logging configuration
policy[p] {
	firewall := firewalls[_]
	not has_valid_logging(firewall)
	p = fugue.deny_resource_with_message(
		firewall,
		sprintf(
			"Network Firewall '%s' must have logging enabled with valid log type (ALERT or FLOW) and destination type (CloudWatchLogs, S3, or KinesisDataFirehose)",
			[firewall.name],
		),
	)
}
