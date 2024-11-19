package rules.mq_auto_minor_version_upgrade_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "MQ.3",
	"title": "Amazon MQ brokers should have automatic minor version upgrade enabled",
	"description": "This control checks if Amazon MQ brokers have automatic minor version upgrades enabled to maintain security patches and improvements.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_MQ.3"]}, "severity": "Low", "reviewer": "ssghait.007@gmail.com"},
}

resource_type := "MULTIPLE"

mq_brokers = fugue.resources("aws_mq_broker")

# Helper function to check if auto minor version upgrade is enabled
is_auto_upgrade_enabled(broker) {
	broker.auto_minor_version_upgrade == true
}

policy[p] {
	broker := mq_brokers[_]
	is_auto_upgrade_enabled(broker)
	p = fugue.allow_resource(broker)
}

policy[p] {
	broker := mq_brokers[_]
	not is_auto_upgrade_enabled(broker)
	p = fugue.deny_resource_with_message(broker, "Amazon MQ broker does not have automatic minor version upgrade enabled")
}
