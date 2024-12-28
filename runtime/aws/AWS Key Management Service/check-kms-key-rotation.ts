import {
	DescribeKeyCommand,
	GetKeyRotationStatusCommand,
	KMSClient,
	ListKeysCommand
} from "@aws-sdk/client-kms";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkKmsKeyRotation(region: string = "us-east-1"): Promise<ComplianceReport> {
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
						message: "KMS key found without KeyId"
					});
					continue;
				}

				try {
					// Get key details to check if it's customer-created and symmetric
					const describeCommand = new DescribeKeyCommand({
						KeyId: key.KeyId
					});
					const keyDetails = await client.send(describeCommand);

					if (!keyDetails.KeyMetadata) {
						results.checks.push({
							resourceName: key.KeyId,
							status: ComplianceStatus.ERROR,
							message: "Unable to get key metadata"
						});
						continue;
					}

					// Skip AWS managed keys and asymmetric keys
					if (
						keyDetails.KeyMetadata.KeyManager === "AWS" ||
						keyDetails.KeyMetadata.KeySpec !== "SYMMETRIC_DEFAULT"
					) {
						continue;
					}

					// Check rotation status for customer-created symmetric keys
					const rotationCommand = new GetKeyRotationStatusCommand({
						KeyId: key.KeyId
					});
					const rotationStatus = await client.send(rotationCommand);

					results.checks.push({
						resourceName: key.KeyId,
						resourceArn: keyDetails.KeyMetadata.Arn,
						status: rotationStatus.KeyRotationEnabled
							? ComplianceStatus.PASS
							: ComplianceStatus.FAIL,
						message: rotationStatus.KeyRotationEnabled ? undefined : "Key rotation is not enabled"
					});
				} catch (error) {
					results.checks.push({
						resourceName: key.KeyId,
						status: ComplianceStatus.ERROR,
						message: `Error checking key rotation status: ${error instanceof Error ? error.message : String(error)}`
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
	const results = await checkKmsKeyRotation(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure rotation for customer-created symmetric CMKs is enabled",
	description:
		"AWS Key Management Service (KMS) allows customers to rotate the backing key which is key material stored within the KMS which is tied to the key ID of the customercreated customer master key (CMK). It is the backing key that is used to perform cryptographic operations such as encryption and decryption. Automated key rotation currently retains all prior backing keys so that decryption of encrypted data can take place transparently. It is recommended that CMK key rotation be enabled for symmetric keys. Key rotation can not be enabled for any asymmetric CMK",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_3.6",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkKmsKeyRotation
} satisfies RuntimeTest;
