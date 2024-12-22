import { CloudTrailClient, DescribeTrailsCommand } from '@aws-sdk/client-cloudtrail';

import {
	printSummary,
	generateSummary,
	type ComplianceReport,
	ComplianceStatus
} from '@codegen/utils/stringUtils';

async function checkCloudTrailEncryption(region: string = 'us-east-1'): Promise<ComplianceReport> {
	const client = new CloudTrailClient({ region });
	const results: ComplianceReport = {
		checks: [],
		metadoc: {
			title: 'CloudTrail should have encryption at-rest enabled',
			description: 'CloudTrail trails must use AWS KMS key encryption for server-side encryption of log files at rest.',
			controls: [
				{
					id: 'AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.2',
					document: 'AWS-Foundational-Security-Best-Practices_v1.0.0'
				}
			]
		}
	};

	try {
		// Get all CloudTrail trails
		const response = await client.send(new DescribeTrailsCommand({}));

		if (!response.trailList || response.trailList.length === 0) {
			results.checks = [
				{
					resourceName: 'No CloudTrail Trails',
					status: ComplianceStatus.NOTAPPLICABLE,
					message: 'No CloudTrail trails found in the account'
				}
			];
			return results;
		}

		// Check each trail for KMS encryption
		for (const trail of response.trailList) {
			if (!trail.Name || !trail.TrailARN) {
				results.checks.push({
					resourceName: 'Unknown Trail',
					status: ComplianceStatus.ERROR,
					message: 'Trail found without name or ARN'
				});
				continue;
			}

			const hasKmsEncryption = trail.KmsKeyId !== undefined && trail.KmsKeyId !== '';

			results.checks.push({
				resourceName: trail.Name,
				resourceArn: trail.TrailARN,
				status: hasKmsEncryption ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasKmsEncryption
					? undefined
					: 'CloudTrail trail is not encrypted with KMS key'
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: 'CloudTrail Check',
				status: ComplianceStatus.ERROR,
				message: `Error checking CloudTrail trails: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? 'ap-southeast-1';
	const results = await checkCloudTrailEncryption(region);
	printSummary(generateSummary(results));
}

export default checkCloudTrailEncryption;