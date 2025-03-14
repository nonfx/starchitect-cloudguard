import { GetBucketPolicyCommand, ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

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
		checks: []
	};

	try {
		// Get all buckets
		const listBucketsResponse = await client.send(new ListBucketsCommand({}));

		if (!listBucketsResponse.Buckets || listBucketsResponse.Buckets.length === 0) {
			results.checks = [
				{
					resourceName: "No S3 Buckets",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No S3 buckets found in the account"
				}
			];
			return results;
		}

		// Check each bucket's policy
		for (const bucket of listBucketsResponse.Buckets) {
			if (!bucket.Name) continue;

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

				const policy: PolicyDocument = JSON.parse(policyResponse.Policy);
				const hasHttpDeny = hasSecureTransportDeny(policy);

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

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkS3DenyHttpAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure S3 Bucket Policy is set to deny HTTP requests",
	description:
		"At the Amazon S3 bucket level, you can configure permissions through a bucket policy making the objects accessible only through HTTPS.",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_2.1.1",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3DenyHttpAccess,
	serviceName: "Amazon Simple Storage Service (Amazon S3)",
	shortServiceName: "s3"
} satisfies RuntimeTest;
