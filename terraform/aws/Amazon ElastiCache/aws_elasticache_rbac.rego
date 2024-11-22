package rules.aws_elasticache_rbac

import data.fugue

__rego__metadoc__ := {
	"id": "5.8",
	"title": "Ensure Authentication and Access Control is Enabled",
	"description": "Individual creates IAM roles that would give specific permission to what the user can and cannot do within that database. The Access Control List (ACLs) allows only specific individuals to access the resources",
	"custom": {
		"controls": {"CIS-AWS-ElastiCache-Benchmark_v1.0.0": ["CIS-AWS-ElastiCache-Benchmark_v1.0.0_5.8"]},
		"severity": "High",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

elasticache_users := fugue.resources("aws_elasticache_user")

elasticache_user_groups := fugue.resources("aws_elasticache_user_group")

elasticache_replication_groups := fugue.resources("aws_elasticache_replication_group")

aws_elasticache_clusters := fugue.resources("aws_elasticache_cluster")

user_has_proper_access(user) {
	user.access_string != ""
}

user_group_has_users(group) {
	count(group.user_ids) > 0
}

replication_group_has_user_groups(rg) {
	count(rg.user_group_ids) > 0
}

policy[p] {
	cluster := aws_elasticache_clusters[_]
	user := elasticache_users[_]
	user_has_proper_access(user)
	p := fugue.allow_resource(user)
}

policy[p] {
	cluster := aws_elasticache_clusters[_]
	group := elasticache_user_groups[_]
	user_group_has_users(group)
	p := fugue.allow_resource(group)
}

policy[p] {
	cluster := aws_elasticache_clusters[_]
	rg := elasticache_replication_groups[_]
	replication_group_has_user_groups(rg)
	p := fugue.allow_resource(rg)
}

policy[p] {
	cluster := aws_elasticache_clusters[_]
	user := elasticache_users[_]
	not user_has_proper_access(user)
	p := fugue.deny_resource_with_message(user, "User does not have proper access control settings.")
}

policy[p] {
	cluster := aws_elasticache_clusters[_]
	group := elasticache_user_groups[_]
	not user_group_has_users(group)
	p := fugue.deny_resource_with_message(group, "User group does not contain any users.")
}

policy[p] {
	cluster := aws_elasticache_clusters[_]
	rg := elasticache_replication_groups[_]
	not replication_group_has_user_groups(rg)
	p := fugue.deny_resource_with_message(rg, "Replication group does not have any user groups assigned.")
}
