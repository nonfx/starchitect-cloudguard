import { GetBucketPolicyCommand, ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface PolicyStatement {
	Effect: string;
	Principal: {
		AWS?: string | string[];
		Service?: string | string[];
	};
	Action: string | string[];
	Resource: string | string[];
	Condition?: {
		StringEquals?: {
			[key: string]: string | string[];
		};
	};
}

interface BucketPolicy {
	Version: string;
	Statement: PolicyStatement[];
}

const BLACKLISTED_ACTIONS = [
	"s3:DeleteBucketPolicy",
	"s3:PutBucketAcl",
	"s3:PutBucketPolicy",
	"s3:PutEncryptionConfiguration",
	"s3:PutObjectAcl",
	"s3:PutObject"
];

function asArray<T>(value: T | T[] | undefined): T[] {
	if (!value) return [];
	return Array.isArray(value) ? value : [value];
}

function getSourceAccountFromCondition(statement: PolicyStatement): string[] {
	if (!statement.Condition?.StringEquals) return [];

	// Case-insensitive check for aws:sourceaccount
	const sourceAccount = statement.Condition.StringEquals["aws:SourceAccount"];
	if (sourceAccount) {
		return asArray(sourceAccount);
	}

	return [];
}

async function checkS3BucketExternalAccess(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const s3Client = new S3Client({ region });
	const stsClient = new STSClient({ region });

	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get current account ID using STS
		const callerIdentity = await stsClient.send(new GetCallerIdentityCommand({}));
		const currentAccountId = callerIdentity.Account;

		if (!currentAccountId) {
			throw new Error("Failed to get current account ID");
		}

		// List all buckets
		const listBucketsResponse = await s3Client.send(new ListBucketsCommand({}));

		if (!listBucketsResponse.Buckets || listBucketsResponse.Buckets.length === 0) {
			results.checks.push({
				resourceName: "No S3 Buckets",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No S3 buckets found in the account"
			});
			return results;
		}

		for (const bucket of listBucketsResponse.Buckets) {
			if (!bucket.Name) continue;

			try {
				const policyResponse = await s3Client.send(
					new GetBucketPolicyCommand({
						Bucket: bucket.Name
					})
				);

				if (!policyResponse.Policy) {
					results.checks.push({
						resourceName: bucket.Name,
						status: ComplianceStatus.PASS,
						message: "Bucket has no policy attached"
					});
					continue;
				}

				const policy: BucketPolicy = JSON.parse(policyResponse.Policy);

				let hasRiskyStatement = false;

				for (const statement of policy.Statement) {
					if (statement.Effect !== "Allow") continue;

					const actions = asArray(statement.Action);

					// Skip if no blacklisted actions
					const hasBlacklistedAction = actions.some(action => BLACKLISTED_ACTIONS.includes(action));
					if (!hasBlacklistedAction) continue;

					// Check AWS principals
					const awsPrincipals = asArray(statement.Principal?.AWS);
					const hasExternalAwsPrincipal = awsPrincipals.some(
						principal =>
							typeof principal === "string" &&
							principal.startsWith("arn:aws:iam:") &&
							!principal.includes(`:${currentAccountId}:`)
					);

					// Check Service principals
					const servicePrincipals = asArray(statement.Principal?.Service);

					// Check aws:SourceAccount condition
					const sourceAccounts = getSourceAccountFromCondition(statement);
					const hasExternalAccountCondition = sourceAccounts.some(
						account => account !== currentAccountId
					);

					// Statement is risky if:
					// 1. Has external AWS principals and no source account condition, or
					// 2. Has service principals and no source account condition
					if (
						(hasExternalAwsPrincipal || servicePrincipals.length > 0) &&
						hasExternalAccountCondition
					) {
						hasRiskyStatement = true;
						break;
					}
				}

				results.checks.push({
					resourceName: bucket.Name,
					status: hasRiskyStatement ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasRiskyStatement
						? "Bucket policy allows blacklisted actions without proper account restrictions"
						: undefined
				});
			} catch (error: any) {
				if (error.name === "NoSuchBucketPolicy") {
					results.checks.push({
						resourceName: bucket.Name,
						status: ComplianceStatus.PASS,
						message: "Bucket has no policy attached"
					});
				} else {
					results.checks.push({
						resourceName: bucket.Name,
						status: ComplianceStatus.ERROR,
						message: `Error checking bucket policy: ${error.message}`
					});
				}
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "S3 Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking S3 buckets: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkS3BucketExternalAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "S3 general purpose bucket policies should restrict access to other AWS accounts",
	description:
		"S3 bucket policies must restrict access to other AWS accounts by preventing specific actions and implementing proper access controls.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_S3.6",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkS3BucketExternalAccess
} satisfies RuntimeTest;
