import { EC2Client, DescribeInstancesCommand } from '@aws-sdk/client-ec2';

import {
	printSummary,
	generateSummary,
} from '~codegen/utils/stringUtils';
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkEc2ImdsV2Compliance(region: string = 'us-east-1'): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let instanceFound = false;

		do {
			const command = new DescribeInstancesCommand({
				NextToken: nextToken,
				Filters: [
					{
						Name: 'instance-state-name',
						Values: ['running', 'stopped']
					}
				]
			});

			const response = await client.send(command);

			if (!response.Reservations || response.Reservations.length === 0) {
				if (!instanceFound) {
					results.checks = [
						{
							resourceName: 'No EC2 Instances',
							status: ComplianceStatus.NOTAPPLICABLE,
							message: 'No EC2 instances found in the region'
						}
					];
					return results;
				}
				break;
			}

			for (const reservation of response.Reservations) {
				if (!reservation.Instances) continue;

				for (const instance of reservation.Instances) {
					instanceFound = true;
					const instanceId = instance.InstanceId || 'Unknown Instance';

					if (!instance.MetadataOptions) {
						results.checks.push({
							resourceName: instanceId,
							status: ComplianceStatus.ERROR,
							message: 'Unable to determine metadata options'
						});
						continue;
					}

					const isCompliant =
						instance.MetadataOptions.HttpEndpoint === 'enabled' &&
						instance.MetadataOptions.HttpTokens === 'required';

					results.checks.push({
						resourceName: instanceId,
						status: isCompliant ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isCompliant
							? undefined
							: 'Instance metadata service is not configured to require IMDSv2'
					});
				}
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks = [
			{
				resourceName: 'EC2 Check',
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
	const results = await checkEc2ImdsV2Compliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: 'Ensure that EC2 Metadata Service only allows IMDSv2',
	description: 'When enabling the Metadata Service on AWS EC2 instances, users have the option of using either Instance Metadata Service Version 1 (IMDSv1; a request/response method) or Instance Metadata Service Version 2 (IMDSv2; a session-oriented method).',
	controls: [
		{
			id: 'CIS-AWS-Foundations-Benchmark_v3.0.0_5.6',
			document: 'CIS-AWS-Foundations-Benchmark_v3.0.0'
		}
	],
	severity: 'MEDIUM',
	execute: checkEc2ImdsV2Compliance
} satisfies RuntimeTest;