package rules.sqs_queues_encrypted

import data.fugue

__rego__metadoc__ := {
	"id": "SQS.1",
	"title": "Amazon SQS queues should be encrypted at rest",
	"description": "Enforce AWS SQS queue encryption at rest using SSE-SQS or SSE-KMS to protect message contents from unauthorized access.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_SQS.1"]}, "severity": "Medium", "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

aws_sqs_queue = fugue.resources("aws_sqs_queue")

# Check if queue is encrypted with either SSE-SQS or KMS
is_encrypted(queue) {
	queue.kms_master_key_id != null
	queue.kms_master_key_id != ""
}

is_encrypted(queue) {
	queue.sqs_managed_sse_enabled == true
}

# Allow queues that are encrypted
policy[p] {
	queue := aws_sqs_queue[_]
	is_encrypted(queue)
	p = fugue.allow_resource(queue)
}

# Deny queues that are not encrypted
policy[p] {
	queue := aws_sqs_queue[_]
	not is_encrypted(queue)
	p = fugue.deny_resource_with_message(queue, "SQS queue must be encrypted at rest using either SSE-SQS or KMS")
}
