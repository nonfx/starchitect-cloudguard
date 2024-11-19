package rules.aws_docdb_monitoring_alerting

import data.fugue

__rego__metadoc__ := {
	"author": "sachin@nonfx.com",
	"id": "7.8.b",
	"title": "Ensure to Implement Monitoring and Alerting - Alerting",
	"description": "This helps by alerting the system if any unusual event has occurred or if a particular threshold has been achieved because the user is able to set a desired interval or the cluster. This then allows system administrators to swiftly correct the situation and avoid subsequent complications if something unusual is happening",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_7.8"]},
		"severity": "High",
	},
}

resource_type := "MULTIPLE"

docdb_clusters = fugue.resources("aws_docdb_cluster")

docdb_cluster_instances = fugue.resources("aws_docdb_cluster_instance")

cw_alarms = fugue.resources("aws_cloudwatch_metric_alarm")

# Function to check if a CloudWatch alarm is associated with a DocumentDB cluster
has_docdb_alarm(cluster, alarms) {
	alarm := alarms[_]
	val := alarm.dimensions.DBClusterIdentifier
	val == cluster.cluster_identifier
}

# Function to check if a CloudWatch alarm is associated with a DocumentDB instance
has_docdb_instance_alarm(instance, alarms) {
	alarm := alarms[_]
	val := alarm.dimensions.DBInstanceIdentifier
	val == instance.id
}

# Policy for DocumentDB clusters
policy[p] {
	cluster := docdb_clusters[_]
	has_docdb_alarm(cluster, cw_alarms)
	p = fugue.allow_resource(cluster)
}

policy[p] {
	cluster := docdb_clusters[_]
	not has_docdb_alarm(cluster, cw_alarms)
	msg := sprintf("DocumentDB Cluster '%s' has no CloudWatch alarms", [cluster.cluster_identifier])
	p = fugue.deny_resource_with_message(cluster, msg)
}

# Policy for DocumentDB instances
policy[p] {
	instance := docdb_cluster_instances[_]
	has_docdb_instance_alarm(instance, cw_alarms)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := docdb_cluster_instances[_]
	not has_docdb_instance_alarm(instance, cw_alarms)
	msg := sprintf("DocumentDB Instance '%s' has no CloudWatch alarms", [instance.identifier])
	p = fugue.deny_resource_with_message(instance, msg)
}
