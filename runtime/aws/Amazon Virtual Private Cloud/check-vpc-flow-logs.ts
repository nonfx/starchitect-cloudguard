import { EC2Client, DescribeVpcsCommand, DescribeFlowLogsCommand } from '@aws-sdk/client-ec2';

import {
	printSummary,
	generateSummary,
	type ComplianceReport,
	ComplianceStatus
} from '@codegen/utils/stringUtils';

async function checkVpcFlowLogsCompliance(region: string = 'us-east-1'): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: [],
		metadoc: {
			title: 'Ensure VPC flow logging is enabled in all VPCs',
			description: 'VPC Flow Logs is a feature that enables you to capture information about the IP traffic going to and from network interfaces in your VPC. After you\'ve created a flow log, you can view and retrieve its data in Amazon CloudWatch Logs. It is recommended that VPC Flow Logs be enabled for packet `Rejects` for VPCs.',
			controls: [
				{
					id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_3.7',
					document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
				}
			]
		}
	};

	try {
		// Get all VPCs
		const vpcsResponse = await client.send(new DescribeVpcsCommand({}));

		if (!vpcsResponse.Vpcs || vpcsResponse.Vpcs.length === 0) {
			results.checks = [
				{
					resourceName: 'No VPCs',
					status: ComplianceStatus.NOTAPPLICABLE,
					message: 'No VPCs found in the region'
				}
			];
			return results;
		}

		// Get all Flow Logs
		const flowLogsResponse = await client.send(new DescribeFlowLogsCommand({}));
		const flowLogs = flowLogsResponse.FlowLogs || [];

		// Check each VPC
		for (const vpc of vpcsResponse.Vpcs) {
			if (!vpc.VpcId) {
				results.checks.push({
					resourceName: 'Unknown VPC',
					status: ComplianceStatus.ERROR,
					message: 'VPC found without VPC ID'
				});
				continue;
			}

			// Find flow logs for this VPC
			const vpcFlowLogs = flowLogs.filter(log => log.ResourceId === vpc.VpcId);

			if (vpcFlowLogs.length === 0) {
				results.checks.push({
					resourceName: vpc.VpcId,
					status: ComplianceStatus.FAIL,
					message: 'VPC does not have any flow logs enabled'
				});
				continue;
			}

			// Check if there's at least one active flow log
			const hasActiveFlowLog = vpcFlowLogs.some(log => log.FlowLogStatus === 'ACTIVE');

			// Check if there's a flow log capturing all traffic
			const hasAllTrafficLog = vpcFlowLogs.some(log => log.TrafficType === 'ALL');

			if (!hasActiveFlowLog) {
				results.checks.push({
					resourceName: vpc.VpcId,
					status: ComplianceStatus.FAIL,
					message: 'VPC does not have any active flow logs'
				});
			} else if (!hasAllTrafficLog) {
				results.checks.push({
					resourceName: vpc.VpcId,
					status: ComplianceStatus.FAIL,
					message: 'VPC flow logs do not capture all traffic types'
				});
			} else {
				results.checks.push({
					resourceName: vpc.VpcId,
					status: ComplianceStatus.PASS,
					message: undefined
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: 'VPC Flow Logs Check',
				status: ComplianceStatus.ERROR,
				message: `Error checking VPC flow logs: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? 'ap-southeast-1';
	const results = await checkVpcFlowLogsCompliance(region);
	printSummary(generateSummary(results));
}

export default checkVpcFlowLogsCompliance;