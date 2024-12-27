import { KMSClient, ListKeysCommand, GetKeyPolicyCommand } from "@aws-sdk/client-kms";
import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

interface PolicyDocument {
	Statement: PolicyStatement[];
}

interface PolicyStatement {
	Effect: string;
	Principal: {
		AWS?: string | string[];
	};
}

async function checkKmsPublicAccess(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new KMSClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// List all KMS keys
		const listKeysResponse = await client.send(new ListKeysCommand({}));

		if (!listKeysResponse.Keys || listKeysResponse.Keys.length === 0) {
			results.checks = [
				{
					resourceName: "No KMS Keys",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No KMS keys found in the region"
				}
			];
			return results;
		}

		// Check each key's policy
		for (const key of listKeysResponse.Keys) {
			if (!key.KeyId) {
				results.checks.push({
					resourceName: "Unknown Key",
					status: ComplianceStatus.ERROR,
					message: "KMS key found without KeyId"
				});
				continue;
			}

			try {
				// Get key policy
				const policyResponse = await client.send(
					new GetKeyPolicyCommand({
						KeyId: key.KeyId,
						PolicyName: "default"
					})
				);

				if (!policyResponse.Policy) {
					results.checks.push({
						resourceName: key.KeyId,
						status: ComplianceStatus.ERROR,
						message: "Unable to retrieve key policy"
					});
					continue;
				}

				const policy: PolicyDocument = JSON.parse(policyResponse.Policy);
				const isPublic = policy.Statement.some(statement => {
					if (statement.Effect !== "Allow") return false;
					const principal = statement.Principal.AWS;
					return principal === "*" || (Array.isArray(principal) && principal.includes("*"));
				});

				results.checks.push({
					resourceName: key.KeyId,
					status: isPublic ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: isPublic ? "KMS key policy allows public access" : undefined
				});
			} catch (error) {
				results.checks.push({
					resourceName: key.KeyId,
					status: ComplianceStatus.ERROR,
					message: `Error checking key policy: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "KMS Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking KMS keys: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkKmsPublicAccess(region);
	printSummary(generateSummary(results));
}

export default {
	title: "KMS keys should not be publicly accessible",
	description:
		"This control checks if KMS keys have policies that allow public access. KMS keys should follow the principle of least privilege and restrict access to authorized principals only.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_KMS.5",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkKmsPublicAccess
} satisfies RuntimeTest;
