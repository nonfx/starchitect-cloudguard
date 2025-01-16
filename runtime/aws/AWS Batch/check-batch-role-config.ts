import { BatchClient } from "@aws-sdk/client-batch";
import { IAMClient, GetRoleCommand } from "@aws-sdk/client-iam";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";
import { getAllComputeEnvironments } from "../../utils/aws/get-all-compute-envs.js";

interface TrustPolicy {
	Version: string;
	Statement: Array<{
		Effect: string;
		Principal: {
			Service: string | string[];
		};
		Action: string | string[];
		Condition?: {
			StringEquals?: {
				["aws:SourceAccount"]?: string;
			};
			StringLike?: {
				["aws:SourceArn"]?: string;
			};
		};
	}>;
}

async function checkBatchRoleCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
	const batchClient = new BatchClient({ region });
	const iamClient = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all compute environments
		const computeEnvironments = await getAllComputeEnvironments(batchClient);

		if (computeEnvironments.length === 0) {
			results.checks = [
				{
					resourceName: "No Compute Environments",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No AWS Batch compute environments found in the region"
				}
			];
			return results;
		}

		for (const env of computeEnvironments) {
			if (!env.computeEnvironmentName || !env.serviceRole) {
				results.checks.push({
					resourceName: env.computeEnvironmentName || "Unknown Environment",
					status: ComplianceStatus.ERROR,
					message: "Compute environment missing name or service role"
				});
				continue;
			}

			try {
				// Extract role name from ARN
				const roleName = env.serviceRole.split("/").pop();
				if (!roleName) {
					throw new Error("Invalid role ARN format");
				}

				// Get role details
				const roleResponse = await iamClient.send(
					new GetRoleCommand({
						RoleName: roleName
					})
				);

				if (!roleResponse.Role?.AssumeRolePolicyDocument) {
					results.checks.push({
						resourceName: env.computeEnvironmentName,
						resourceArn: env.serviceRole,
						status: ComplianceStatus.FAIL,
						message: "Service role missing trust policy"
					});
					continue;
				}

				const trustPolicy: TrustPolicy = JSON.parse(
					decodeURIComponent(roleResponse.Role.AssumeRolePolicyDocument)
				);
				console.log(trustPolicy);

				// Check if trust policy has required condition keys
				const hasRequiredConditions = trustPolicy.Statement.some(
					stmt =>
						stmt.Condition?.StringEquals?.["aws:SourceAccount"] &&
						stmt.Condition?.StringLike?.["aws:SourceArn"]
				);

				results.checks.push({
					resourceName: env.computeEnvironmentName,
					resourceArn: env.serviceRole,
					status: hasRequiredConditions ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasRequiredConditions
						? undefined
						: "Service role missing required condition keys for confused deputy prevention"
				});
			} catch (error) {
				results.checks.push({
					resourceName: env.computeEnvironmentName,
					resourceArn: env.serviceRole,
					status: ComplianceStatus.ERROR,
					message: `Error checking service role: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking Batch compute environments: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkBatchRoleCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "AWS Batch",
	shortServiceName: "batch",
	title: "Ensure Batch roles are configured for cross-service confused deputy prevention",
	description:
		"The Cross-service confused deputy problem is a security issue where an entity that doesn't have permission to perform an action can coerce a more-privileged entity to perform the action",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_5.2",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkBatchRoleCompliance
} satisfies RuntimeTest;
