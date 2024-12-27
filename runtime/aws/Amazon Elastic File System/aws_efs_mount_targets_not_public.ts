import { EFSClient, DescribeMountTargetsCommand } from "@aws-sdk/client-efs";
import { EC2Client, DescribeSubnetsCommand } from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkEfsMountTargetsPublicSubnets(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const efsClient = new EFSClient({ region });
	const ec2Client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all mount targets
		const mountTargetsResponse = await efsClient.send(new DescribeMountTargetsCommand({}));

		if (!mountTargetsResponse.MountTargets || mountTargetsResponse.MountTargets.length === 0) {
			results.checks.push({
				resourceName: "No EFS Mount Targets",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No EFS mount targets found in the region"
			});
			return results;
		}

		// Get subnet information for all mount targets
		for (const mountTarget of mountTargetsResponse.MountTargets) {
			if (!mountTarget.SubnetId || !mountTarget.MountTargetId) {
				results.checks.push({
					resourceName: "Unknown Mount Target",
					status: ComplianceStatus.ERROR,
					message: "Mount target found without subnet ID or mount target ID"
				});
				continue;
			}

			try {
				// Get subnet details
				const subnetResponse = await ec2Client.send(
					new DescribeSubnetsCommand({
						SubnetIds: [mountTarget.SubnetId]
					})
				);

				const subnet = subnetResponse.Subnets?.[0];
				if (!subnet) {
					results.checks.push({
						resourceName: mountTarget.MountTargetId,
						status: ComplianceStatus.ERROR,
						message: `Subnet ${mountTarget.SubnetId} not found`
					});
					continue;
				}

				// Check if subnet is public (has MapPublicIpOnLaunch enabled)
				const isPublic = subnet.MapPublicIpOnLaunch === true;

				results.checks.push({
					resourceName: mountTarget.MountTargetId,
					status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: isPublic
						? `Mount target is associated with public subnet ${mountTarget.SubnetId}`
						: undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: mountTarget.MountTargetId,
					status: ComplianceStatus.ERROR,
					message: `Error checking subnet: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Region Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking EFS mount targets: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEfsMountTargetsPublicSubnets(region);
	printSummary(generateSummary(results));
}

export default {
	title: "EFS mount targets should not be associated with a public subnet",
	description:
		"This control checks if EFS mount targets are associated with private subnets to prevent unauthorized access from the internet.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EFS.6",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEfsMountTargetsPublicSubnets
} satisfies RuntimeTest;
