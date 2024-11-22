package rules.aws_elasticache_automatic_updates

import data.fugue

__rego__metadoc__ := {
	"id": "5.4",
	"title": "Ensure Automatic Updates and Patching are Enabled",
	"description": "Enabling automatic updates and patching for Amazon ElastiCache ensures that your ElastiCache clusters run the latest software versions with important security fixes and enhancements.",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.4"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

elasticache_clusters = fugue.resources("aws_elasticache_cluster")

auto_minor_version_upgrade_enabled(cluster) {
	cluster.auto_minor_version_upgrade == true
}

policy[p] {
	cluster := elasticache_clusters[_]
	auto_minor_version_upgrade_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := elasticache_clusters[_]
	not auto_minor_version_upgrade_enabled(cluster)
	msg := sprintf("ElastiCache cluster '%s' does not have automatic minor version upgrades enabled", [cluster.id])
	p = fugue.deny_resource_with_message(cluster, msg)
}
