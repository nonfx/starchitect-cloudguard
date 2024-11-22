package rules.elasticache_replication_group_auto_failover

import data.fugue

__rego__metadoc__ := {
	"id": "ElastiCache.3",
	"title": "ElastiCache replication groups should have automatic failover enabled",
	"description": "ElastiCache replication groups must enable automatic failover to ensure high availability and minimize downtime during node failures.",
	"custom": {"controls": {"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_ElastiCache.3"]}, "severity": "Medium"},
}

resource_type := "MULTIPLE"

# Get all ElastiCache replication groups
replication_groups = fugue.resources("aws_elasticache_replication_group")

# Helper to check if automatic failover is enabled
is_auto_failover_enabled(group) {
	group.automatic_failover_enabled == true
}

# Allow replication groups with automatic failover enabled
policy[p] {
	group := replication_groups[_]
	is_auto_failover_enabled(group)
	p = fugue.allow_resource(group)
}

# Deny replication groups without automatic failover enabled
policy[p] {
	group := replication_groups[_]
	not is_auto_failover_enabled(group)
	p = fugue.deny_resource_with_message(
		group,
		"ElastiCache replication group should have automatic failover enabled",
	)
}
