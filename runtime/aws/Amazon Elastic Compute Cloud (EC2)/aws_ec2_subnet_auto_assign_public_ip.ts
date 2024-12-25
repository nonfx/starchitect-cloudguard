import { EC2Client, DescribeSubnetsCommand } from '@aws-sdk/client-ec2';

import {
	printSummary,
	generateSummary,
} from '~codegen/utils/stringUtils';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkSubnetAutoAssignPublicIp(region: string = 'us-east-1'): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all subnets in the region
		const response = await client.send(new DescribeSubnetsCommand({}));

		if (!response.Subnets || response.Subnets.length === 0) {
			results.checks = [
				{
					resourceName: 'No Subnets',
					status: ComplianceStatus.NOTAPPLICABLE,
					message: 'No subnets found in the region'
				}
			];
			return results;
		}

		// Check each subnet's MapPublicIpOnLaunch setting
		for (const subnet of response.Subnets) {
			if (!subnet.SubnetId) {
				results.checks.push({
					resourceName: 'Unknown Subnet',
					status: ComplianceStatus.ERROR,
					message: 'Subnet found without Subnet ID'
				});
				continue;
			}

			const subnetName = subnet.Tags?.find(tag => tag.Key === 'Name')?.Value || subnet.SubnetId;

			results.checks.push({
				resourceName: subnetName,
				resourceArn: `arn:aws:ec2:${region}:${subnet.OwnerId}:subnet/${subnet.SubnetId}`,
				status: subnet.MapPublicIpOnLaunch ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: subnet.MapPublicIpOnLaunch
					? 'Subnet automatically assigns public IP addresses'
					: undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: 'Region Check',
				status: ComplianceStatus.ERROR,
				message: `Error checking subnets: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? 'ap-southeast-1';
	const results = await checkSubnetAutoAssignPublicIp(region);
	printSummary(generateSummary(results));
}

export default {
	title: 'Amazon EC2 subnets should not automatically assign public IP addresses',
	description: 'This control checks if EC2 subnets are configured to automatically assign public IP addresses. The control fails if the subnet\'s MapPublicIpOnLaunch attribute is set to true.',
	controls: [
		{
			id: 'AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.15',
			document: 'AWS-Foundational-Security-Best-Practices_v1.0.0'
		}
	],
	severity: 'MEDIUM',
	execute: checkSubnetAutoAssignPublicIp
} satisfies RuntimeTest;