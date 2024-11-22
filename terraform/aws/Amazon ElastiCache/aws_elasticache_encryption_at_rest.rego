package rules.aws_elasticache_encryption_at_rest

import data.fugue

__rego__metadoc__ := {
	"id": "5.3.a",
	"title": "Ensure Encryption at Rest and in Transit is configured - at rest",
	"description": "Enabling encryption at rest and in transit for Amazon ElastiCache helps protect your data when it is stored and transmitted",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.3"]},"author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

# aws_elasticache_replication_group is only used for Redis
elasticache_replication_groups = fugue.resources("aws_elasticache_replication_group")

encryption_at_rest_enabled(resource) {
	resource.at_rest_encryption_enabled == true
}

policy[p] {
	resource := elasticache_replication_groups[_]
	not encryption_at_rest_enabled(resource)
	p = fugue.deny_resource_with_message(resource, "ElastiCache replication group does not have encryption at rest enabled")
}

policy[p] {
	resource := elasticache_replication_groups[_]
	encryption_at_rest_enabled(resource)
	p = fugue.allow_resource(resource)
}
