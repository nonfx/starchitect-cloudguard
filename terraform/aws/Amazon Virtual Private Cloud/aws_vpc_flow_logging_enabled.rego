package rules.aws_vpc_flow_logs

__rego__metadoc__ := {
	"author": "chandra@nonfx.com",
	"id": "3.7",
	"title": "Ensure VPC flow logging is enabled in all VPCs",
	"description": "VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you've created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet `Rejects` for VPCs.",
	"custom": {"controls": {"CIS-AWS-Foundations-Benchmark_v3.0.0": ["CIS-AWS-Foundations-Benchmark_v3.0.0_3.7"]}, "severity": "Low", "author": "llmagent", "reviewer": "ssghait.007@gmail.com"},
}

import data.fugue

# Define the type of resource this policy will apply to
resource_type := "MULTIPLE"

# Get all VPCs
vpcs = fugue.resources("aws_vpc")

# Get all VPC Flow Logs
flow_logs = fugue.resources("aws_flow_log")

# Check if VPC Flow Logs are enabled for each VPC
policy[r] {
	vpc = vpcs[_]
	flow_log_enabled(vpc.id)
	r = fugue.allow_resource(vpc)
}

policy[r] {
	vpc = vpcs[_]
	vpc_id := vpc.id
	not flow_log_enabled(vpc_id)
	msg := sprintf("VPC with ID %s does not have Flow Logs enabled.", [vpc_id])
	r = fugue.deny_resource_with_message(vpc, msg)
}

# Helper function to check if a Flow Log is enabled for a given VPC ID
flow_log_enabled(vpc_id) {
	some i
	flow_log = flow_logs[i]
	flow_log.vpc_id == vpc_id
}

# Example check for specific Flow Log configuration
policy[r] {
	flow_log = flow_logs[_]
	not flow_log.traffic_type == "ALL"
	msg := sprintf("Flow Log for VPC %s does not capture all traffic (should be 'ALL').", [flow_log.vpc_id])
	r = fugue.deny_resource_with_message(flow_log, msg)
}
