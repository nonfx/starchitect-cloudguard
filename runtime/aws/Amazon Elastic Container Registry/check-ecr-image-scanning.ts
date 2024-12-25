import { DescribeRepositoriesCommand, ECRClient } from "@aws-sdk/client-ecr";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkEcrImageScanningCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new ECRClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all ECR repositories
		const repositories = await client.send(new DescribeRepositoriesCommand({}));

		if (!repositories.repositories || repositories.repositories.length === 0) {
			results.checks = [
				{
					resourceName: "No ECR Repositories",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No ECR repositories found in the region"
				}
			];
			return results;
		}

		// Check each repository for image scanning configuration
		for (const repo of repositories.repositories) {
			if (!repo.repositoryName || !repo.repositoryArn) {
				results.checks.push({
					resourceName: "Unknown Repository",
					status: ComplianceStatus.ERROR,
					message: "Repository found without name or ARN"
				});
				continue;
			}

			const isScanningEnabled = repo.imageScanningConfiguration?.scanOnPush === true;

			results.checks.push({
				resourceName: repo.repositoryName,
				resourceArn: repo.repositoryArn,
				status: isScanningEnabled ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isScanningEnabled ? undefined : "Image scanning is not enabled for this repository"
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking ECR repositories: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEcrImageScanningCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECR private repositories should have image scanning configured",
	description:
		"This control checks whether ECR private repositories have image scanning enabled. The control fails if scan_on_push is not enabled.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECR.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEcrImageScanningCompliance
} satisfies RuntimeTest;