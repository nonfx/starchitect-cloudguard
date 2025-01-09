import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { LightsailClient, GetBucketsCommand } from "@aws-sdk/client-lightsail";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface PolicyStatement {
	Effect: string;
	Action: string | string[];
	Resource: string | string[];
}

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement | PolicyStatement[];
}

interface BucketPolicyCheck {
	bucketName: string;
	hasPolicyAccess: boolean;
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

function extractBucketNamesFromArn(resource: string): string | null {
	const match = resource.match(/arn:aws:s3:::([^\/]*)/);
	if (!match || !match[1]) {
		return null;
	}
	return match[1];
}

async function getLightsailBuckets(region: string): Promise<string[]> {
	const client = new LightsailClient({ region });
	const buckets: string[] = [];

	try {
		let pageToken: string | undefined;

		do {
			const command = new GetBucketsCommand({
				pageToken
			});

			const response = await client.send(command);

			if (response.buckets) {
				buckets.push(
					...response.buckets
						.map(bucket => bucket.name)
						.filter((name): name is string => name !== undefined)
				);
			}

			pageToken = response.nextPageToken;
		} while (pageToken);
	} catch (error) {
		throw new Error(
			`Failed to fetch Lightsail buckets: ${error instanceof Error ? error.message : String(error)}`
		);
	}

	return buckets;
}

function checkBucketAccess(
	policyDocument: PolicyDocument,
	buckets: Set<string>
): Map<string, boolean> {
	const statements = asArray(policyDocument.Statement);
	const bucketAccess = new Map<string, boolean>();

	// Initialize all buckets as not having access
	buckets.forEach(bucket => bucketAccess.set(bucket, false));

	for (const statement of statements) {
		if (statement.Effect !== "Allow") continue;

		const actions = asArray(statement.Action);
		const resources = asArray(statement.Resource);

		// Skip if no S3 actions are allowed
		if (!actions.some(action => action === "s3:*" || action.startsWith("s3:"))) continue;

		// Check each resource for bucket access
		resources.forEach(resource => {
			if (typeof resource !== "string") return;

			const bucketName = extractBucketNamesFromArn(resource);
			if (bucketName && buckets.has(bucketName)) {
				bucketAccess.set(bucketName, true);
			}
		});
	}

	return bucketAccess;
}

function hasLightsailAccess(policyDocument: PolicyDocument): boolean {
	const statements = asArray(policyDocument.Statement);

	for (const statement of statements) {
		if (statement.Effect !== "Allow") continue;

		const actions = asArray(statement.Action);
		if (actions.includes("lightsail:*")) return true;
	}

	return false;
}

async function checkLightsailBucketAccess(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new IAMClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	// Track which buckets have passed in any policy
	const passingBuckets = new Set<string>();
	// Track all discovered buckets
	const processedBuckets = new Set<string>();

	// Fetch Lightsail buckets
	let bucketNames: string[];
	try {
		bucketNames = await getLightsailBuckets(region);
		if (bucketNames.length === 0) {
			return {
				checks: [
					{
						resourceName: "Lightsail Buckets",
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No Lightsail buckets found in the region"
					}
				]
			};
		}
	} catch (error) {
		return {
			checks: [
				{
					resourceName: "Lightsail Buckets",
					status: ComplianceStatus.ERROR,
					message: `Failed to fetch Lightsail buckets: ${error instanceof Error ? error.message : String(error)}`
				}
			]
		};
	}

	const bucketSet = new Set(bucketNames);

	try {
		let marker: string | undefined;
		let policyFound = false;

		do {
			const listCommand = new ListPoliciesCommand({
				Marker: marker,
				Scope: "Local"
			});

			const response = await client.send(listCommand);

			if (!response.Policies || response.Policies.length === 0) {
				if (!policyFound) {
					results.checks = bucketNames.map(bucket => ({
						resourceName: bucket,
						status: ComplianceStatus.FAIL,
						message: "No IAM policies found to manage bucket access"
					}));
					return results;
				}
				break;
			}

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

					const policyDocument = parsePolicyDocument(
						decodeURIComponent(versionResponse.PolicyVersion.Document)
					);

					// Check for Lightsail access
					const hasLightsail = hasLightsailAccess(policyDocument);

					// Check bucket access
					const bucketAccessMap = checkBucketAccess(policyDocument, bucketSet);

					// Process each bucket's access status
					bucketAccessMap.forEach((hasAccess, bucketName) => {
						processedBuckets.add(bucketName);
						if (hasAccess && hasLightsail) {
							// Mark bucket as passing and add to results if not already passing
							if (!passingBuckets.has(bucketName)) {
								passingBuckets.add(bucketName);
								results.checks.push({
									resourceName: bucketName,
									resourceArn: policy.Arn,
									status: ComplianceStatus.PASS,
									message: `Bucket access properly managed by policy ${policyName}`
								});
							}
						}
					});
				} catch (error) {
					results.checks.push({
						resourceName: policyName,
						resourceArn: policy.Arn,
						status: ComplianceStatus.ERROR,
						message: `Error analyzing policy: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			marker = response.Marker;
		} while (marker);

		// Only add failing checks for buckets that haven't passed in any policy
		bucketNames.forEach(bucket => {
			if (!passingBuckets.has(bucket)) {
				results.checks.push({
					resourceName: bucket,
					status: ComplianceStatus.FAIL,
					message: "No policy found properly managing this bucket"
				});
			}
		});
	} catch (error) {
		results.checks = [
			{
				resourceName: "IAM Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking IAM policies: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkLightsailBucketAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure you are using an IAM policy to manage access to buckets in Lightsail",
	description:
		"The following policy grants a user access to manage specific buckets in the Amazon Lightsail object storage service",
	controls: [
		{
			id: "CIS-AWS-Compute-Services-Benchmark_v1.0.0_3.7",
			document: "CIS-AWS-Compute-Services-Benchmark_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkLightsailBucketAccess,
	serviceName: "Amazon Lightsail",
	shortServiceName: "lightsail"
} satisfies RuntimeTest;
