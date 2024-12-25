import { EC2Client, DescribeInstancesCommand, DescribeNetworkInterfacesCommand } from '@aws-sdk/client-ec2';

import {
	printSummary,
	generateSummary,
} from '~codegen/utils/stringUtils';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkEc2MultipleEniCompliance(region: string = 'us-east-1'): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all EC2 instances
		const instances = await client.send(new DescribeInstancesCommand({}));

		if (!instances.Reservations || instances.Reservations.length === 0) {
			results.checks = [
				{
					resourceName: 'No EC2 Instances',
					status: ComplianceStatus.NOTAPPLICABLE,
					message: 'No EC2 instances found in the region'
				}
			];
			return results;
		}

		// Process each instance
		for (const reservation of instances.Reservations) {
			if (!reservation.Instances) continue;

			for (const instance of reservation.Instances) {
				if (!instance.InstanceId) {
					results.checks.push({
						resourceName: 'Unknown Instance',
						status: ComplianceStatus.ERROR,
						message: 'Instance found without ID'
					});
					continue;
				}

				try {
					// Get network interfaces for this instance
					const networkInterfaces = await client.send(
						new DescribeNetworkInterfacesCommand({
							Filters: [
								{
									Name: 'attachment.instance-id',
									Values: [instance.InstanceId]
								}
							]
						})
					);

					const eniCount = networkInterfaces.NetworkInterfaces?.length || 0;

					results.checks.push({
						resourceName: instance.InstanceId,
						resourceArn: `arn:aws:ec2:${region}:${instance.OwnerId}:instance/${instance.InstanceId}`,
						status: eniCount <= 1 ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message:
							eniCount > 1
								? `Instance has ${eniCount} ENIs attached. Should only have one ENI`
								: undefined
					});
				} catch (error) {
					results.checks.push({
						resourceName: instance.InstanceId,
						status: ComplianceStatus.ERROR,
						message: `Error checking network interfaces: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: 'Region Check',
				status: ComplianceStatus.ERROR,
				message: `Error checking EC2 instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? 'ap-southeast-1';
	const results = await checkEc2MultipleEniCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: 'Amazon EC2 instances should not use multiple ENIs',
	description: 'This control checks if EC2 instances use multiple Elastic Network Interfaces (ENIs). The control fails if an instance has more than one ENI attached.',
	controls: [
		{
			id: 'AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.17',
			document: 'AWS-Foundational-Security-Best-Practices_v1.0.0'
		}
	],
	severity: 'MEDIUM',
	execute: checkEc2MultipleEniCompliance
} satisfies RuntimeTest;