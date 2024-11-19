package rules.aws_elasticache_secure_access

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "5.1",
	"title": "Ensure Secure Access to ElastiCache",
	"description": "Securing access to Amazon ElastiCache involves implementing appropriate authentication and authorization mechanisms.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.1"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

elasticache_replication_groups := fugue.resources("aws_elasticache_replication_group")

auth_enabled(replication_group) {
	replication_group.auth_token != null
}

encryption_enabled(replication_group) {
	replication_group.transit_encryption_enabled
}

policy[p] {
	replication_group := elasticache_replication_groups[_]
	auth_enabled(replication_group)
	encryption_enabled(replication_group)
	p = fugue.allow_resource(replication_group)
}

policy[p] {
	replication_group := elasticache_replication_groups[_]
	not auth_enabled(replication_group)
	p = fugue.deny_resource_with_message(replication_group, "ElastiCache replication group does not have authentication enabled.")
}

policy[p] {
	replication_group := elasticache_replication_groups[_]
	not encryption_enabled(replication_group)
	p = fugue.deny_resource_with_message(replication_group, "ElastiCache replication group does not have encryption enabled.")
}
