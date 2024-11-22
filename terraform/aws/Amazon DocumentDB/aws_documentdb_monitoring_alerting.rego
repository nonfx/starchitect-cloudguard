package rules.aws_documentdb_monitoring

import data.fugue

__rego__metadoc__ := {
	"id": "7.8.b",
	"title": "Ensure to Implement Monitoring and Alerting - Monitoring",
	"description": "This helps by alerting the system if any unusual event has occurred or if a particular threshold has been achieved because the user is able to set a desired interval or the cluster. This then allows system administrators to swiftly correct the situation and avoid subsequent complications if something unusual is happening.",
	"custom": {"controls":{"CIS-AWS-Database-Services-Benchmark_v1.0.0":["CIS-AWS-Database-Services-Benchmark_v1.0.0_7.8"]},"severity":"Medium","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

documentdb_clusters := fugue.resources("aws_docdb_cluster")

has_alerting_enabled(cluster) {
	cluster.enabled_cloudwatch_logs_exports[_] != ""
}

policy[p] {
	cluster := documentdb_clusters[_]
	has_alerting_enabled(cluster)
	p := fugue.allow_resource(cluster)
}

policy[p] {
	cluster := documentdb_clusters[_]
	not has_alerting_enabled(cluster)
	p := fugue.deny_resource_with_message(cluster, "Monitoring not enabled for this Amazon DocumentDB cluster.")
}
