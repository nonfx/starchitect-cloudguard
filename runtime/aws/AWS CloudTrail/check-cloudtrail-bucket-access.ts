import { CloudTrailClient, DescribeTrailsCommand } from "@aws-sdk/client-cloudtrail";
import { S3Client, GetBucketPolicyCommand, GetBucketAclCommand } from "@aws-sdk/client-s3";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface BucketPolicy {
	Statement: Array<{
		Effect: string;
		Principal: string | { [key: string]: string | string[] };
		Action: string | string[];
		Resource: string | string[];
	}>;
}

async function isS3BucketPublic(s3Client: S3Client, bucketName: string): Promise<boolean> {
	try {
		// Check bucket policy
		try {
			const policyCommand = new GetBucketPolicyCommand({ Bucket: bucketName });
			const policyResponse = await s3Client.send(policyCommand);

			if (policyResponse.Policy) {
				const policy: BucketPolicy = JSON.parse(policyResponse.Policy);

				// Check for public access in policy
				const hasPublicAccess = policy.Statement.some(statement => {
					const principal =
						typeof statement.Principal === "string"
							? statement.Principal
							: JSON.stringify(statement.Principal);
					return (
						statement.Effect === "Allow" && (principal.includes("*") || principal.includes("AWS:*"))
					);
				});

				if (hasPublicAccess) return true;
			}
		} catch (error: any) {
			if (error.name !== "NoSuchBucketPolicy") throw error;
		}

		// Check bucket ACL
		const aclCommand = new GetBucketAclCommand({ Bucket: bucketName });
		const aclResponse = await s3Client.send(aclCommand);

		return (
			aclResponse.Grants?.some(
				grant =>
					grant.Grantee?.URI === "http://acs.amazonaws.com/groups/global/AllUsers" ||
					grant.Grantee?.URI === "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
			) ?? false
		);
	} catch (error) {
		throw new Error(
			`Error checking bucket access: ${error instanceof Error ? error.message : String(error)}`
		);
	}
}

async function checkCloudTrailBucketAccess(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const cloudTrailClient = new CloudTrailClient({ region });
	const s3Client = new S3Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get CloudTrail trails
		const trailsResponse = await cloudTrailClient.send(new DescribeTrailsCommand({}));

		if (!trailsResponse.trailList || trailsResponse.trailList.length === 0) {
			results.checks.push({
				resourceName: "CloudTrail",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No CloudTrail trails found"
			});
			return results;
		}

		// Check each trail's S3 bucket
		for (const trail of trailsResponse.trailList) {
			if (!trail.S3BucketName) {
				results.checks.push({
					resourceName: trail.Name || "Unknown Trail",
					status: ComplianceStatus.ERROR,
					message: "Trail has no S3 bucket configured"
				});
				continue;
			}

			try {
				const isPublic = await isS3BucketPublic(s3Client, trail.S3BucketName);

				results.checks.push({
					resourceName: trail.S3BucketName,
					resourceArn: trail.TrailARN,
					status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: isPublic ? "CloudTrail S3 bucket is publicly accessible" : undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: trail.S3BucketName,
					resourceArn: trail.TrailARN,
					status: ComplianceStatus.ERROR,
					message: `Error checking bucket: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "CloudTrail Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking CloudTrail: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION;
	const results = await checkCloudTrailBucketAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible",
	description:
		"CloudTrail logs a record of every API call made in your account. These log files are stored in an S3 bucket. CIS recommends that the S3 bucket policy, or access control list (ACL), applied to the S3 bucket that CloudTrail logs to prevents public access to the CloudTrail logs. Allowing public access to CloudTrail log content might aid an adversary in identifying weaknesses in the affected account's use or configuration.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_CloudTrail.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkCloudTrailBucketAccess
} satisfies RuntimeTest;
