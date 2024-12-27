import { GetBucketPolicyCommand, ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { generateSummary, printSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

interface PolicyStatement {
	Effect: string;
	Principal: string | { [key: string]: string | string[] };
	Action: string | string[];
	Resource?: string | string[];
	Condition?: {
		Bool?: {
			[key: string]: string;
		};
	};
}

interface PolicyDocument {
	Version: string;
	Statement: PolicyStatement[];
}

function hasSSLRequirement(policyDocument: PolicyDocument): boolean {
	return policyDocument.Statement.some(statement => {
		return (
			statement.Effect === "Deny" &&
			(statement.Principal === "*" ||
				(typeof statement.Principal === "object" && statement.Principal["AWS"] === "*")) &&
			(statement.Action === "s3:*" ||
				(Array.isArray(statement.Action) && statement.Action.includes("s3:*"))) &&
			statement.Condition?.Bool?.["aws:SecureTransport"] === "false"
		);
	});
}

async function checkS3SSLRequired(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new S3Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all S3 buckets
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
				const policyCommand = new GetBucketPolicyCommand({
					Bucket: bucket.Name
				});

				const policyResponse = await client.send(policyCommand);

				if (policyResponse.Policy) {
					const policyDocument = JSON.parse(policyResponse.Policy) as PolicyDocument;
					const hasSSL = hasSSLRequirement(policyDocument);

					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: hasSSL ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: hasSSL
							? undefined
							: "Bucket policy does not enforce SSL/TLS using aws:SecureTransport condition"
					});
				}
			} catch (error: any) {
				if (error.name === "NoSuchBucketPolicy") {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.FAIL,
						message: "No bucket policy exists to enforce SSL/TLS"
					});
				} else {
					results.checks.push({
						resourceName: bucket.Name,
						resourceArn: `arn:aws:s3:::${bucket.Name}`,
						status: ComplianceStatus.ERROR,
						message: `Error checking bucket policy: ${error.message}`
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
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkS3SSLRequired(region);
	printSummary(generateSummary(results));
}

export default {
	title: "S3 buckets should require SSL/TLS for all requests",
	description:
		"This control checks if S3 buckets require SSL/TLS encryption for all requests by verifying bucket policies include aws:SecureTransport condition.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_S3.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3SSLRequired
} satisfies RuntimeTest;
