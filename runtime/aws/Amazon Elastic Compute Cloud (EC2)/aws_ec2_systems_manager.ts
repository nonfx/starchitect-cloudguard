import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { IAMClient, GetInstanceProfileCommand } from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkEc2SystemsManagerCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const ec2Client = new EC2Client({ region });
	const iamClient = new IAMClient({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all EC2 instances
		const instances = await ec2Client.send(new DescribeInstancesCommand({}));

		if (!instances.Reservations || instances.Reservations.length === 0) {
			results.checks.push({
				resourceName: "No EC2 Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No EC2 instances found in the region"
			});
			return results;
		}

		for (const reservation of instances.Reservations) {
			if (!reservation.Instances) continue;

			for (const instance of reservation.Instances) {
				if (!instance.InstanceId) continue;

				// Check if instance has an IAM instance profile
				if (!instance.IamInstanceProfile?.Arn) {
					results.checks.push({
						resourceName: instance.InstanceId,
						status: ComplianceStatus.FAIL,
						message: "EC2 instance does not have an IAM instance profile attached"
					});
					continue;
				}

				try {
					// Get the instance profile details
					const profileName = instance.IamInstanceProfile.Arn.split("/").pop();
					if (!profileName) throw new Error("Invalid instance profile ARN");

					const profileCommand = new GetInstanceProfileCommand({
						InstanceProfileName: profileName
					});

					const profileResponse = await iamClient.send(profileCommand);

					// Check if profile has role with SSM policy
					const hasSSMPolicy = profileResponse.InstanceProfile?.Roles?.some(role =>
						role.AssumeRolePolicyDocument?.includes("AmazonSSMManagedInstanceCore")
					);

					results.checks.push({
						resourceName: instance.InstanceId,
						resourceArn: instance.IamInstanceProfile.Arn,
						status: hasSSMPolicy ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasSSMPolicy
							? undefined
							: "Instance profile does not have AmazonSSMManagedInstanceCore policy attached"
					});
				} catch (error) {
					results.checks.push({
						resourceName: instance.InstanceId,
						status: ComplianceStatus.ERROR,
						message: `Error checking instance profile: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Region Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking EC2 instances: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEc2SystemsManagerCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure use of AWS Systems Manager to manage EC2 instances",
	description:
		"An inventory and management of Amazon Elastic Compute Cloud (Amazon EC2) instances is made possible with AWS Systems Manager.",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_2.9",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEc2SystemsManagerCompliance,
	serviceName: "Amazon Elastic Compute Cloud (EC2)",
	shortServiceName: "ec2"
} satisfies RuntimeTest;
