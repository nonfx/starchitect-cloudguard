package rules.mq_broker_audit_logs_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "MQ.2",
	"title": "ActiveMQ brokers should stream audit logs to CloudWatch",
	"description": "This control checks if Amazon MQ ActiveMQ brokers are configured to stream audit logs to CloudWatch Logs for security monitoring and compliance.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_MQ.2"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

mq_brokers = fugue.resources("aws_mq_broker")

# Helper function to check if audit logs are enabled
has_audit_logging(broker) {
	broker.logs[_].audit == true
}

policy[p] {
	broker := mq_brokers[_]
	has_audit_logging(broker)
	p = fugue.allow_resource(broker)
}

policy[p] {
	broker := mq_brokers[_]
	not has_audit_logging(broker)
	p = fugue.deny_resource_with_message(broker, "ActiveMQ broker must have audit logging enabled and streamed to CloudWatch Logs")
}
