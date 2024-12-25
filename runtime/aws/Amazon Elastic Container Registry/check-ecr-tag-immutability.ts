import { DescribeRepositoriesCommand, ECRClient } from "@aws-sdk/client-ecr";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

async function checkEcrTagImmutability(region: string = "us-east-1"): Promise<ComplianceReport> {
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

		// Check each repository for tag immutability
		for (const repo of repositories.repositories) {
			if (!repo.repositoryName || !repo.repositoryArn) {
				results.checks.push({
					resourceName: "Unknown Repository",
					status: ComplianceStatus.ERROR,
					message: "Repository found without name or ARN"
				});
				continue;
			}

			const isImmutable = repo.imageTagMutability === "IMMUTABLE";

			results.checks.push({
				resourceName: repo.repositoryName,
				resourceArn: repo.repositoryArn,
				status: isImmutable ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isImmutable ? undefined : "ECR repository does not have tag immutability enabled"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Region Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking ECR repositories: ${error instanceof Error ? error.message : String(error)}`
		});
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEcrTagImmutability(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECR private repositories should have tag immutability configured",
	description:
		"This control checks if private ECR repositories have tag immutability enabled. Immutable tags prevent overwriting of container images, ensuring consistent deployments and reducing security risks.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECR.2",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEcrTagImmutability
} satisfies RuntimeTest;