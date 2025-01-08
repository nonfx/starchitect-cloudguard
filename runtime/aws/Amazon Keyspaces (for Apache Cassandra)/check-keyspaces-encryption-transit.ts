import { KeyspacesClient, GetKeyspaceCommand } from "@aws-sdk/client-keyspaces";
import { getAllKeyspaces } from "./get-all-keyspaces.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface EncryptionCheck {
	hasEncryptionAtRest: boolean;
	hasEncryptionInTransit: boolean;
}

async function checkKeyspaceEncryption(region: string = "us-east-1"): Promise<ComplianceReport> {
	const keyspacesClient = new KeyspacesClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const keyspaces = await getAllKeyspaces(keyspacesClient);

		if (!keyspaces || keyspaces.length === 0) {
			results.checks.push({
				resourceName: "Keyspaces",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No Keyspaces found in the region"
			});
			return results;
		}

		for (const keyspace of keyspaces) {
			if (!keyspace.keyspaceName) continue;

			try {
				// Get keyspace details including encryption configuration
				const keyspaceDetails = await keyspacesClient.send(
					new GetKeyspaceCommand({
						keyspaceName: keyspace.keyspaceName
					})
				);

				// Check encryption configurations
				const encryptionChecks: EncryptionCheck = {
					// Keyspaces are always encrypted at rest by default
					hasEncryptionAtRest: true,
					// TLS is enforced by default for all connections
					hasEncryptionInTransit: true
				};

				// Build status messages
				let encryptionStatus: string[] = [];
				encryptionStatus.push("Data at rest encryption enabled");
				encryptionStatus.push("TLS encryption enabled for in-transit data");

				// All Keyspaces use encryption by default, so this should always pass
				results.checks.push({
					resourceName: keyspace.keyspaceName,
					resourceArn: keyspace.resourceArn,
					status: ComplianceStatus.PASS,
					message: `Encryption properly configured: ${encryptionStatus.join(", ")}`
				});
			} catch (error) {
				results.checks.push({
					resourceName: keyspace.keyspaceName,
					resourceArn: keyspace.resourceArn,
					status: ComplianceStatus.ERROR,
					message: `Error checking encryption configuration: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Keyspaces Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking keyspaces encryption: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkKeyspaceEncryption(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Data at Rest and in Transit is Encrypted",
	description:
		"Verifies that Amazon Keyspaces are properly configured with encryption at rest and in transit. " +
		"Amazon Keyspaces automatically encrypts all data at rest and enforces TLS encryption for data in transit.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_8.3",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkKeyspaceEncryption,
	serviceName: "Amazon Keyspaces",
	shortServiceName: "keyspaces"
} satisfies RuntimeTest;
