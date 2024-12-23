import { S3Client, GetBucketPolicyCommand, ListBucketsCommand } from "@aws-sdk/client-s3";

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
	Condition?: {
		Bool?: {
			[key: string]: string | string[];
		};
	};
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

function hasSecureTransportDeny(policyDocument: PolicyDocument): boolean {
	const statements = asArray(policyDocument.Statement);

	return statements.some(statement => {
		const actions = asArray(statement.Action);
		const validActions = new Set(["s3:GetObject", "s3:*", "*"]);

		return (
			statement.Effect === "Deny" &&
			actions.some(action => validActions.has(action)) &&
			statement.Condition?.Bool?.["aws:SecureTransport"] === "false"
		);
	});
}

async function checkS3DenyHttpAccess(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new S3Client({ region });
	const results: ComplianceReport = {
		checks: [],
		metadoc: {
			title: "Ensure S3 Bucket Policy is set to deny HTTP requests",
			description:
				"At the Amazon S3 bucket level, you can configure permissions through a bucket policy making the objects accessible only through HTTPS.",
			controls: [
				{
					id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.1",
					document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
				}
			]
		}
	};

	try {
		// Get all S3 buckets
		const listBucketsResponse = await client.send(new ListBucketsCommand({}));

		if (!listBucketsResponse.Buckets || listBucketsResponse.Buckets.length === 0) {
			results.checks = [
				{
					resourceName: "No S3 Buckets",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No S3 buckets found"
				}
			];
			return results;
		}

		// Check each bucket's policy
		for (const bucket of listBucketsResponse.Buckets) {
			if (!bucket.Name) {
				results.checks.push({
					resourceName: "Unknown Bucket",
					status: ComplianceStatus.ERROR,
					message: "Bucket found without name"
				});
				continue;
			}

			try {
				const policyResponse = await client.send(
					new GetBucketPolicyCommand({ Bucket: bucket.Name })
				);

				if (!policyResponse.Policy) {
					results.checks.push({
						resourceName: bucket.Name,
						status: ComplianceStatus.FAIL,
						message: "Bucket has no policy configured"
					});
					continue;
				}

				const policyDocument = parsePolicyDocument(policyResponse.Policy);
				const hasHttpDeny = hasSecureTransportDeny(policyDocument);

				results.checks.push({
					resourceName: bucket.Name,
					status: hasHttpDeny ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
					message: hasHttpDeny ? undefined : "Bucket policy does not deny HTTP requests"
				});
			} catch (error: any) {
				if (error.name === "NoSuchBucketPolicy") {
					results.checks.push({
						resourceName: bucket.Name,
						status: ComplianceStatus.FAIL,
						message: "Bucket has no policy configured"
					});
				} else {
					results.checks.push({
						resourceName: bucket.Name,
						status: ComplianceStatus.ERROR,
						message: `Error checking bucket policy: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "S3 Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking S3 buckets: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkS3DenyHttpAccess(region);
	printSummary(generateSummary(results));
}

export default checkS3DenyHttpAccess;
