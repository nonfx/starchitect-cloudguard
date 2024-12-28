import { DescribeKeyCommand, KMSClient, ListKeysCommand } from "@aws-sdk/client-kms";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkKmsKeysDeletionStatus(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new KMSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let marker: string | undefined;
		let keyFound = false;

		do {
			const listCommand = new ListKeysCommand({
				Marker: marker
			});

			const response = await client.send(listCommand);

			if (!response.Keys || response.Keys.length === 0) {
				if (!keyFound) {
					results.checks = [
						{
							resourceName: "No KMS Keys",
							status: ComplianceStatus.NOTAPPLICABLE,
							message: "No KMS keys found in the region"
						}
					];
					return results;
				}
				break;
			}

			for (const key of response.Keys) {
				keyFound = true;
				if (!key.KeyId) {
					results.checks.push({
						resourceName: "Unknown Key",
						status: ComplianceStatus.ERROR,
						message: "KMS key found without Key ID"
					});
					continue;
				}

				try {
					const describeCommand = new DescribeKeyCommand({
						KeyId: key.KeyId
					});

					const keyDetails = await client.send(describeCommand);

					if (!keyDetails.KeyMetadata) {
						results.checks.push({
							resourceName: key.KeyId,
							status: ComplianceStatus.ERROR,
							message: "Unable to fetch key metadata"
						});
						continue;
					}

					const isDeletionScheduled = keyDetails.KeyMetadata.DeletionDate !== undefined;

					results.checks.push({
						resourceName: key.KeyId,
						resourceArn: keyDetails.KeyMetadata.Arn,
						status: isDeletionScheduled ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
						message: isDeletionScheduled
							? `KMS key is scheduled for deletion on ${keyDetails.KeyMetadata.DeletionDate}`
							: undefined
					});
				} catch (error) {
					results.checks.push({
						resourceName: key.KeyId,
						status: ComplianceStatus.ERROR,
						message: `Error checking key details: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			marker = response.NextMarker;
		} while (marker);
	} catch (error) {
		results.checks = [
			{
				resourceName: "KMS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking KMS keys: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkKmsKeysDeletionStatus(region);
	printSummary(generateSummary(results));
}

export default {
	title: "AWS KMS keys should not be scheduled for deletion",
	description:
		"This control checks if any KMS keys are scheduled for deletion. KMS keys and their encrypted data cannot be recovered once deleted, potentially causing permanent data loss.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_KMS.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkKmsKeysDeletionStatus
} satisfies RuntimeTest;
