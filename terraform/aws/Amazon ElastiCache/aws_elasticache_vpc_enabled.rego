package rules.aws_elasticache_vpc_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "5.5",
	"title": "Ensure Virtual Private Cloud (VPC) is Enabled for ElastiCache",
	"description": "Implementing VPC security best practices for Amazon ElastiCache involves configuring your Virtual Private Cloud (VPC) and associated resources to enhance the security of your ElastiCache clusters.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.5"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

elasticache_clusters = fugue.resources("aws_elasticache_cluster")

elasticache_subnet_groups = fugue.resources("aws_elasticache_subnet_group")

vpc_enabled(cluster) {
	elasticache_subnet_group = elasticache_subnet_groups[_]
	elasticache_subnet_group.name == cluster.subnet_group_name
	count(elasticache_subnet_group.subnet_ids) > 0
}

policy[p] {
	cluster := elasticache_clusters[_]
	vpc_enabled(cluster)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := elasticache_clusters[_]
	not vpc_enabled(cluster)
	msg := sprintf("ElastiCache cluster '%s' is not configured to use a VPC. Enable VPC for enhanced security.", [cluster.id])
	p = fugue.deny_resource_with_message(cluster, msg)
}
