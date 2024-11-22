package rules.aws_aurora_audit_logging_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "2.6",
	"title": "Ensure Database Audit Logging is Enabled",
	"description": "Amazon Aurora provides advanced auditing capabilities through AWS CloudTrail and Amazon RDS Database Activity Streams",
	"custom": {
		"controls": {"CIS-AWS-Database-Services-Benchmark_v1.0.0": ["CIS-AWS-Database-Services-Benchmark_v1.0.0_2.6"]},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

cloudtrails = fugue.resources("aws_cloudtrail")

aurora_clusters = fugue.resources("aws_rds_cluster")

activity_streams = fugue.resources("aws_rds_cluster_activity_stream")

cloudtrail_logging_all_regions(trail) {
	trail.is_multi_region_trail == true
	trail.include_global_service_events == true
}

aurora_activity_stream_enabled(cluster) {
	activity_stream := activity_streams[_]
	activity_stream.mode != ""
	activity_stream.kms_key_id != ""
}

policy[p] {
	resource := cloudtrails[_]
	cloudtrail_logging_all_regions(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := aurora_clusters[_]
	aurora_activity_stream_enabled(resource)
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := activity_streams[_]
	p = fugue.allow_resource(resource)
}

policy[p] {
	resource := cloudtrails[_]
	not cloudtrail_logging_all_regions(resource)
	p = fugue.deny_resource_with_message(resource, "CloudTrail is not configured to log all regions and global service events")
}

policy[p] {
	resource := aurora_clusters[_]
	not aurora_activity_stream_enabled(resource)
	p = fugue.deny_resource_with_message(resource, "Database Activity Streams is not enabled for this Aurora cluster")
}
