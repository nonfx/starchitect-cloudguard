package rules.aws_ec2_detailed_monitoring

import data.fugue

__rego__metadoc__ := {
	"author": "rajat@nonfx.com",
	"id": "2.6",
	"title": "Ensure detailed monitoring is enable for production EC2 Instances",
	"description": "Ensure that detailed monitoring is enabled for your Amazon EC2 instances.",
	"custom": {
		"controls": {"CIS-AWS-Compute-Services-Benchmark_v1.0.0": ["CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.6"]},
		"severity": "Medium",
	},
}

resource_type := "MULTIPLE"

ec2_instances := fugue.resources("aws_instance")

detailed_monitoring_enabled(instance) {
	instance.monitoring == true
}

policy[p] {
	instance := ec2_instances[_]
	detailed_monitoring_enabled(instance)
	p = fugue.allow_resource(instance)
}

policy[p] {
	instance := ec2_instances[_]
	not detailed_monitoring_enabled(instance)
	msg := sprintf("EC2 instance '%s' in Production environment does not have detailed monitoring enabled", [instance.id])
	p = fugue.deny_resource_with_message(instance, msg)
}
