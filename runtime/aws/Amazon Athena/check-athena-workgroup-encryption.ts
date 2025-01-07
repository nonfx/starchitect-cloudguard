import { AthenaClient, ListWorkGroupsCommand, GetWorkGroupCommand } from "@aws-sdk/client-athena";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkAthenaWorkgroupEncryption(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new AthenaClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		let nextToken: string | undefined;
		let workgroupsFound = false;

		do {
			// Get list of all workgroups
			const listCommand = new ListWorkGroupsCommand({
				NextToken: nextToken
			});
			const response = await client.send(listCommand);

			if (!response.WorkGroups || response.WorkGroups.length === 0) {
				if (!workgroupsFound) {
					results.checks.push({
						resourceName: "No Athena Workgroups",
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No Athena workgroups found in the region"
					});
					return results;
				}
				break;
			}

			workgroupsFound = true;

			// Check each workgroup's encryption configuration
			for (const workgroup of response.WorkGroups) {
				const workgroupName = workgroup.Name || "Unknown Workgroup";

				try {
					const getCommand = new GetWorkGroupCommand({
						WorkGroup: workgroupName
					});
					const workgroupDetails = await client.send(getCommand);

					const encryptionConfig =
						workgroupDetails.WorkGroup?.Configuration?.ResultConfiguration?.EncryptionConfiguration;

					const isEncrypted =
						encryptionConfig?.EncryptionOption === "SSE_S3" ||
						(["SSE_KMS", "CSE_KMS"].includes(encryptionConfig?.EncryptionOption || "") &&
							encryptionConfig?.KmsKey);

					results.checks.push({
						resourceName: workgroupName,
						status: isEncrypted ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
						message: isEncrypted
							? undefined
							: "Athena workgroup is not encrypted at rest or missing KMS key configuration"
					});
				} catch (error) {
					results.checks.push({
						resourceName: workgroupName,
						status: ComplianceStatus.ERROR,
						message: `Error checking workgroup: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			}

			nextToken = response.NextToken;
		} while (nextToken);
	} catch (error) {
		results.checks.push({
			resourceName: "Athena Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Athena workgroups: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkAthenaWorkgroupEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Athena workgroups should be encrypted at rest",
	description:
		"This control checks if an Athena workgroup is encrypted at rest. The control fails if an Athena workgroup isn't encrypted at rest.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_Athena.1",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkAthenaWorkgroupEncryption,
	serviceName: "Amazon Athena",
	shortServiceName: "athena"
} satisfies RuntimeTest;
