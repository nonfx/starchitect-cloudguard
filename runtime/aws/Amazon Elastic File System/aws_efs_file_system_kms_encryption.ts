import { EFSClient, DescribeFileSystemsCommand } from "@aws-sdk/client-efs";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEfsEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EFSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all EFS file systems
		const response = await client.send(new DescribeFileSystemsCommand({}));

		if (!response.FileSystems || response.FileSystems.length === 0) {
			results.checks = [
				{
					resourceName: "No EFS File Systems",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No EFS file systems found in the region"
				}
			];
			return results;
		}

		// Check each file system for encryption
		for (const fs of response.FileSystems) {
			if (!fs.FileSystemId) {
				results.checks.push({
					resourceName: "Unknown File System",
					status: ComplianceStatus.ERROR,
					message: "File system found without ID"
				});
				continue;
			}

			const isEncrypted = fs.Encrypted === true && fs.KmsKeyId !== undefined;

			results.checks.push({
				resourceName: fs.FileSystemId,
				resourceArn: fs.FileSystemArn,
				status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isEncrypted ? undefined : "EFS file system is not encrypted with KMS"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking EFS file systems: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEfsEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure that encryption is enabled for EFS file systems",
	description: "EFS data should be encrypted at rest using AWS KMS (Key Management Service).",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.4.1",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEfsEncryption,
	serviceName: "Amazon Elastic File System",
	shortServiceName: "efs"
} satisfies RuntimeTest;
