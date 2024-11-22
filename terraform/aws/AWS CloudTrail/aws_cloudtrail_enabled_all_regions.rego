package rules.aws_cloudtrail_enabled_all_regions

import data.fugue

__rego__metadoc__ := {
	"id": "3.1",
	"title": "Ensure CloudTrail is enabled in all regions",
	"description": "AWS CloudTrail is a web service that records AWS API calls for your account and delivers log files to you. The recorded information includes the identity of the API caller, the time of the API call, the source IP address of the API caller, the request parameters, and the response elements returned by the AWS service. CloudTrail provides a history of AWS API calls for an account, including API calls made via the Management Console, SDKs, command line tools, and higher-level AWS services (such as CloudFormation).",
	"custom": {"controls":{"CIS-AWS-Foundations-Benchmark_v3.0.0":["CIS-AWS-Foundations-Benchmark_v3.0.0_3.1"]},"severity":"Low","author":"Starchitect Agent"},
}

resource_type := "MULTIPLE"

cloudtrails := fugue.resources("aws_cloudtrail")

cloudtrail_global(trail) {
	trail.is_multi_region_trail = true
	trail.enable_logging = true
}

policy[p] {
	trail := cloudtrails[_]
	trail_name := trail.name
	not cloudtrail_global(trail)
	msg := sprintf("CloudTrail '%s' is not properly configured. Ensure it is multi-region, enabled, includes global service events, and has log file validation enabled.", [trail_name])
	p = fugue.deny_resource_with_message(trail, msg)
}

policy[p] {
	trail = cloudtrails[_]
	cloudtrail_global(trail)
	p = fugue.allow_resource(trail)
}
