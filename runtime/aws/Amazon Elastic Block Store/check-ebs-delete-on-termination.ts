import {
	EC2Client,
	DescribeInstancesCommand,
	DescribeVolumesCommand,
	type Instance,
	type Reservation,
	type BlockDeviceMapping
} from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEbsDeleteOnTermination(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all EC2 instances with pagination
		let nextToken: string | undefined;
		let allReservations: Reservation[] = [];

		do {
			const instances = await client.send(
				new DescribeInstancesCommand({
					NextToken: nextToken
				})
			);

			if (instances.Reservations) {
				allReservations = allReservations.concat(instances.Reservations);
			}

			nextToken = instances.NextToken;
		} while (nextToken);

		if (!allReservations || allReservations.length === 0) {
			results.checks = [
				{
					resourceName: "No EC2 Instances",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No EC2 instances found in the region"
				}
			];
			return results;
		}

		// Check each instance's volumes
		for (const reservation of allReservations) {
			for (const instance of reservation.Instances || []) {
				if (!instance.InstanceId) continue;

				const processedVolumes = new Set<string>();

				// Check root volume
				if (instance.RootDeviceName && instance.BlockDeviceMappings) {
					const rootMapping = instance.BlockDeviceMappings.find(
						(mapping: BlockDeviceMapping) => mapping.DeviceName === instance.RootDeviceName
					);
					if (rootMapping?.Ebs) {
						const volumeId = rootMapping.Ebs.VolumeId || "root-volume";
						processedVolumes.add(volumeId);
						results.checks.push({
							resourceName: `${instance.InstanceId}:${volumeId}`,
							status: rootMapping.Ebs.DeleteOnTermination
								? ComplianceStatus.PASS
								: ComplianceStatus.FAIL,
							message: rootMapping.Ebs.DeleteOnTermination
								? undefined
								: `Root volume is not set to delete on termination`
						});
					}
				}

				// Check other EBS volumes
				if (instance.BlockDeviceMappings) {
					for (const mapping of instance.BlockDeviceMappings) {
						if (mapping.Ebs) {
							const volumeId = mapping.Ebs.VolumeId || mapping.DeviceName || "unknown-volume";
							// Skip if we've already processed this volume (e.g. as root volume)
							if (processedVolumes.has(volumeId)) continue;

							results.checks.push({
								resourceName: `${instance.InstanceId}:${volumeId}`,
								status: mapping.Ebs.DeleteOnTermination
									? ComplianceStatus.PASS
									: ComplianceStatus.FAIL,
								message: mapping.Ebs.DeleteOnTermination
									? undefined
									: `Volume is not set to delete on termination`
							});
						}
					}
				}
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "EC2 Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking EC2 instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkEbsDeleteOnTermination(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon Elastic Block Store",
	shortServiceName: "ebs",
	title:
		"Ensure EBS volumes attached to an EC2 instance is marked for deletion upon instance termination",
	description:
		"This rule ensures that Amazon Elastic Block Store volumes that are attached to Amazon Elastic Compute Cloud (Amazon EC2) instances are marked for deletion when an instance is terminated. If an Amazon EBS volume isn't deleted when the instance that it's attached to is terminated, it may violate the concept of least functionality.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.12",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEbsDeleteOnTermination
} satisfies RuntimeTest;
