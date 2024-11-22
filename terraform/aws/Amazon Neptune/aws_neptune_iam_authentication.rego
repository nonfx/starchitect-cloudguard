package rules.aws_neptune_iam_authentication

import data.fugue

__rego__metadoc__ := {
	"id": "9.4.a",
	"title": "Ensure Authentication and Access Control is Enabled - authentication",
	"description": "This helps ensure that there are specific IAM roles and policies that are given the necessary information within a Neptune DB cluster to operate as needed.",
	"custom": {"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_9.4"]}, "author": "Starchitect Agent"},
}

resource_type := "MULTIPLE"

neptune_clusters := fugue.resources("aws_neptune_cluster")

policy[p] {
	resource := neptune_clusters[_]
	resource.iam_database_authentication_enabled == true
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := neptune_clusters[_]
	resource.iam_database_authentication_enabled == false
	p = fugue.deny_resource_with_message(resource, "IAM database authentication is not enabled for this Neptune cluster")
}
