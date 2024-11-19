package rules.aws_neptune_network_security_enabled

import data.fugue

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "9.1",
	"title": "Ensure Network Security is Enabled for AWS Neptune",
	"description": "This helps ensure that all the necessary security measurements are taken to prevent a cyber-attack on AWS Neptune instances, such as utilizing VPC, creating certain inbound and outbound rules, and ACLs.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_9.1"]}},
}

resource_type := "MULTIPLE"

neptune_clusters := fugue.resources("aws_neptune_cluster")

security_groups := fugue.resources("aws_security_group")

acls := fugue.resources("aws_network_acl")

has_required_security_settings(neptune) {
	count(neptune.vpc_security_group_ids) > 0
}

policy[p] {
	neptune := neptune_clusters[_]
	has_required_security_settings(neptune)
	p = fugue.allow_resource(neptune)
}

policy[p] {
	neptune := neptune_clusters[_]
	not has_required_security_settings(neptune)
	msg := sprintf("AWS Neptune Cluster '%s' does not have the required security settings.", [neptune.cluster_identifier])
	p = fugue.deny_resource_with_message(neptune, msg)
}
