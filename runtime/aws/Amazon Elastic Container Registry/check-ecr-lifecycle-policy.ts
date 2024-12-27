import {
	DescribeRepositoriesCommand,
	ECRClient,
	GetLifecyclePolicyCommand
} from "@aws-sdk/client-ecr";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

interface EcrRepository {
	name: string;
	arn: string;
}

async function hasLifecyclePolicy(client: ECRClient, repository: EcrRepository): Promise<boolean> {
	try {
		const command = new GetLifecyclePolicyCommand({
			repositoryName: repository.name
		});
		await client.send(command);
		return true;
	} catch (error: any) {
		if (error.name === "LifecyclePolicyNotFoundException") {
			return false;
		}
		throw error;
	}
}

async function checkEcrLifecyclePolicyCompliance(
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

		// Check each repository for lifecycle policy
		for (const repo of repositories.repositories) {
			if (!repo.repositoryName || !repo.repositoryArn) {
				results.checks.push({
					resourceName: "Unknown Repository",
					status: ComplianceStatus.ERROR,
					message: "Repository found without name or ARN"
				});
				continue;
			}

			const repository: EcrRepository = {
				name: repo.repositoryName,
				arn: repo.repositoryArn
			};

			try {
				const hasPolicy = await hasLifecyclePolicy(client, repository);

				results.checks.push({
					resourceName: repository.name,
					resourceArn: repository.arn,
					status: hasPolicy ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasPolicy
						? undefined
						: "ECR repository does not have a lifecycle policy configured"
				});
			} catch (error) {
				results.checks.push({
					resourceName: repository.name,
					resourceArn: repository.arn,
					status: ComplianceStatus.ERROR,
					message: `Error checking lifecycle policy: ${error instanceof Error ? error.message : String(error)}`
				});
			}
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

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEcrLifecyclePolicyCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title: "ECR repositories should have at least one lifecycle policy configured",
	description:
		"This control checks if Amazon ECR repositories have at least one lifecycle policy configured. Lifecycle policies help manage container images by automatically cleaning up unused images based on age or count criteria.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_ECR.3",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEcrLifecyclePolicyCompliance
} satisfies RuntimeTest;
