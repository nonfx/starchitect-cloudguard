import {
	EC2Client,
	DescribeVolumesCommand,
	GetEbsEncryptionByDefaultCommand
} from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEbsVolumeEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Check if EBS encryption by default is enabled
		const encryptionCommand = new GetEbsEncryptionByDefaultCommand({});
		const encryptionResponse = await client.send(encryptionCommand);

		if (!encryptionResponse.EbsEncryptionByDefault) {
			results.checks.push({
				resourceName: "Default EBS Encryption",
				status: ComplianceStatus.FAIL,
				message: "EBS encryption by default is not enabled in this region"
			});
			return results;
		}

		// Get all EBS volumes with pagination
		let nextToken: string | undefined;
		let allVolumes: any[] = [];

		do {
			const volumesCommand = new DescribeVolumesCommand({
				NextToken: nextToken
			});
			const volumesResponse = await client.send(volumesCommand);

			if (volumesResponse.Volumes) {
				allVolumes = allVolumes.concat(volumesResponse.Volumes);
			}

			nextToken = volumesResponse.NextToken;
		} while (nextToken);

		if (allVolumes.length === 0) {
			results.checks.push({
				resourceName: "No EBS Volumes",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No EBS volumes found in the region"
			});
			return results;
		}

		// Check each volume's encryption status
		for (const volume of allVolumes) {
			if (!volume.VolumeId) {
				results.checks.push({
					resourceName: "Unknown Volume",
					status: ComplianceStatus.ERROR,
					message: "Volume found without Volume ID"
				});
				continue;
			}

			results.checks.push({
				resourceName: volume.VolumeId,
				status: volume.Encrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: volume.Encrypted ? undefined : "EBS volume is not encrypted"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Region Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking EBS volumes: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEbsVolumeEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon Elastic Block Store",
	shortServiceName: "ebs",
	title: "Ensure EBS Volume Encryption is Enabled in all Regions",
	description:
		"Elastic Compute Cloud (EC2) supports encryption at rest when using the Elastic Block Store (EBS) service. While disabled by default, forcing encryption at EBS volume creation is supported.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.2.1",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		},
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.2.1",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "LOW",
	execute: checkEbsVolumeEncryption
} satisfies RuntimeTest;
