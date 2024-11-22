package rules.aws_cloudtrail_log_file_validation_enabled

import data.fugue

__rego__metadoc__ := {
	"id": "3.2_CloudTrail.4",
	"title": "Ensure CloudTrail log file validation is enabled",
	"description": "CloudTrail log file validation creates a digitally signed digest file containing a hash of each log that CloudTrail writes to S3. These digest files can be used to determine whether a log file was changed, deleted, or unchanged after CloudTrail delivered the log. It is recommended that file validation be enabled on all CloudTrails.",
	"custom": {
		"controls": {
			"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_3.2"],
			"AWS-Foundational-Security-Best-Practices_v1.0.0": ["AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.4"],
		},
		"severity": "Medium",
		"author": "Starchitect Agent",
	},
}

resource_type := "MULTIPLE"

cloudtrails := fugue.resources("aws_cloudtrail")

cloudtrail_log_validation_enabled(trail) {
	trail.enable_log_file_validation = true
}

policy[p] {
	trail := cloudtrails[_]
	trail_name := trail.name
	not cloudtrail_log_validation_enabled(trail)
	msg := sprintf("CloudTrail '%s' does not have log file validation enabled. Ensure log file validation is enabled to protect log integrity.", [trail_name])
	p = fugue.deny_resource_with_message(trail, msg)
}

policy[p] {
	trail = cloudtrails[_]
	cloudtrail_log_validation_enabled(trail)
	p = fugue.allow_resource(trail)
}
