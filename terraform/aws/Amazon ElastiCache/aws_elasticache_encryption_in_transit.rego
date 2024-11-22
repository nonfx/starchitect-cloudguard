package rules.aws_elasticache_encryption_in_transit

import data.fugue

__rego__metadoc__ := {
	"id": "5.3.b",
	"title": "Ensure Encryption at Rest and in Transit is configured - in transit",
	"description": "Enabling encryption at rest and in transit for Amazon ElastiCache helps protect your data when it is stored and transmitted",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_5.3"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

elasticache_clusters = fugue.resources("aws_elasticache_cluster")

elasticache_replication_groups = fugue.resources("aws_elasticache_replication_group")

encryption_in_transit_enabled(resource) {
	resource.transit_encryption_enabled == true
}

in_vpc(resource) {
	resource.subnet_group_name != ""
}

allow_resource_with_message(resource, message) = ret {
	ret := fugue.allow({
		"resource": resource,
		"message": message,
	})
}

# Although versions can be checked through regula but supported versions can change and rule can become outdated. therefore showing message for user to check version
policy[p] {
	resource := get_resource
	encryption_in_transit_enabled(resource)
	msg := "Please verify the Redis version is supported for in-transit encryption. Refer to the AWS ElastiCache documentation for supported versions https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html"
	p = allow_resource_with_message(resource, msg)
}

policy[p] {
	resource := elasticache_replication_groups[_]
	in_vpc(resource)
	msg := "Please verify the Redis version is supported for in-transit encryption. Refer to the AWS ElastiCache documentation for supported versions https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/CacheNodes.SupportedTypes.html"
	p = allow_resource_with_message(resource, msg)
}

policy[p] {
	resource := get_resource
	not encryption_in_transit_enabled(resource)
	msg := "ElastiCache cluster does not have encryption in transit enabled"
	p = fugue.deny_resource_with_message(resource, msg)
}

policy[p] {
	resource := elasticache_replication_groups[_]
	not in_vpc(resource)
	msg := "ElastiCache cluster is not running in a VPC"
	p = fugue.deny_resource_with_message(resource, msg)
}

# if both pass or fail, only 1 PASS or FAIL would be returned in result
get_resource = resource {
	count(elasticache_clusters) > 0
	resource := elasticache_clusters[_]
} else = resource {
	count(elasticache_replication_groups) > 0
	resource := elasticache_replication_groups[_]
}
