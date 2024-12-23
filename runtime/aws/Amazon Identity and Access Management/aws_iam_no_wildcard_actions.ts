import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";

import {
	printSummary,
	generateSummary,
	type ComplianceReport,
	ComplianceStatus
} from "@codegen/utils/stringUtils";

interface PolicyStatement {
	Effect: string;
	Action: string | string[];
	Resource: string | string[];
}

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement | PolicyStatement[];
}

function asArray<T>(value: T | T[]): T[] {
	return Array.isArray(value) ? value : [value];
}

function parsePolicyDocument(policyJson: string): PolicyDocument {
	try {
		return JSON.parse(policyJson);
	} catch (error) {
		throw new Error(`Invalid policy document: ${error}`);
	}
}

function hasWildcardActions(policyDocument: PolicyDocument): boolean {
	const statements = asArray(policyDocument.Statement);

	return statements.some(statement => {
		if (statement.Effect !== "Allow") return false;
		const actions = asArray(statement.Action);
		return actions.some(action => {
			return /:\*$|^\*$/.test(action);
		});
	});
}

async function checkIamWildcardActions(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: [],
		metadoc: {
			title: "IAM customer managed policies should not allow wildcard actions for services",
			description: "This control checks if IAM customer managed policies have wildcard actions for services. Using wildcard actions in IAM policies may grant users more privileges than needed.",
			controls: [
				{
					id: "AWS-Foundational-Security-Best-Practices_v1.0.0_IAM.21",
					document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
				}
			]
		}
	};

	try {
		let marker: string | undefined;
		let policyFound = false;

		do {
			try {
				const listCommand = new ListPoliciesCommand({
					Marker: marker,
					Scope: "Local", // Only check customer managed policies
					OnlyAttached: true
				});

				const response = await client.send(listCommand);

				if (!response.Policies || response.Policies.length === 0) {
					if (!policyFound) {
						results.checks = [
							{
								resourceName: "No IAM Policies",
								status: ComplianceStatus.NOTAPPLICABLE,
								message: "No customer managed policies found"
							}
						];
						return results;
					}
					break;
				}

				// Check each policy
				for (const policy of response.Policies) {
					policyFound = true;
					const policyName = policy.PolicyName || "Unknown Policy";

					if (!policy.Arn || !policy.DefaultVersionId) {
						results.checks.push({
							resourceName: policyName,
							status: ComplianceStatus.ERROR,
							message: "Policy missing ARN or version ID"
						});
						continue;
					}

					try {
						// Get policy version details
						const versionCommand = new GetPolicyVersionCommand({
							PolicyArn: policy.Arn,
							VersionId: policy.DefaultVersionId
						});

						const versionResponse = await client.send(versionCommand);

						if (!versionResponse.PolicyVersion?.Document) {
							results.checks.push({
								resourceName: policyName,
								resourceArn: policy.Arn,
								status: ComplianceStatus.ERROR,
								message: "Policy version document is empty"
							});
							continue;
						}

						try {
							const policyDocument = parsePolicyDocument(
								decodeURIComponent(versionResponse.PolicyVersion.Document)
							);

							const hasWildcard = hasWildcardActions(policyDocument);

							results.checks.push({
								resourceName: policyName,
								resourceArn: policy.Arn,
								status: hasWildcard ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
								message: hasWildcard
									? "Policy contains wildcard actions for services"
									: undefined
							});
						} catch (error) {
							results.checks.push({
								resourceName: policyName,
								resourceArn: policy.Arn,
								status: ComplianceStatus.ERROR,
								message: `Error parsing policy document: ${error instanceof Error ? error.message : String(error)}`
							});
						}
					} catch (error) {
						results.checks.push({
							resourceName: policyName,
							resourceArn: policy.Arn,
							status: ComplianceStatus.ERROR,
							message: `Error fetching policy version: ${error instanceof Error ? error.message : String(error)}`
						});
					}
				}

				marker = response.Marker;
			} catch (error) {
				results.checks.push({
					resourceName: "Policy List",
					status: ComplianceStatus.ERROR,
					message: `Error listing policies: ${error instanceof Error ? error.message : String(error)}`
				});
				break;
			}
		} while (marker);
	} catch (error) {
		results.checks = [
			{
				resourceName: "IAM Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking IAM policies: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkIamWildcardActions(region);
	printSummary(generateSummary(results));
}

export default checkIamWildcardActions;