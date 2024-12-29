import {
	DescribeInstancesCommand,
	DescribeInstanceAttributeCommand,
	EC2Client
} from "@aws-sdk/client-ec2";

import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport } from "../../types.js";

function containsSensitiveData(userData: string): boolean {
	// Common patterns for sensitive data
	const sensitivePatterns = [
		/password[^\w]*(:|=)\s*['"]?[\w\-!@#$%^&*()]+['"]?/i,
		/secret[^\w]*(:|=)\s*['"]?[\w\-!@#$%^&*()]+['"]?/i,
		/key[^\w]*(:|=)\s*['"]?[\w\-!@#$%^&*()]+['"]?/i,
		/token[^\w]*(:|=)\s*['"]?[\w\-!@#$%^&*()]+['"]?/i,
		/credential[^\w]*(:|=)\s*['"]?[\w\-!@#$%^&*()]+['"]?/i,
		/aws_access_key_id[^\w]*(:|=)\s*['"]?[\w\-!@#$%^&*()]+['"]?/i,
		/aws_secret_access_key[^\w]*(:|=)\s*['"]?[\w\-!@#$%^&*()]+['"]?/i
	];

	return sensitivePatterns.some(pattern => pattern.test(userData));
}

async function checkEc2UserDataSecrets(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// First get all instance IDs
		let instanceIds: string[] = [];
		let nextToken: string | undefined;

		do {
			const command = new DescribeInstancesCommand({
				NextToken: nextToken
			});

			const response = await client.send(command);

			if (!response.Reservations || response.Reservations.length === 0) {
				if (results.checks.length === 0) {
					results.checks.push({
						resourceName: "No EC2 Instances",
						status: ComplianceStatus.NOTAPPLICABLE,
						message: "No EC2 instances found in the region"
					});
				}
				break;
			}

			for (const reservation of response.Reservations) {
				if (!reservation.Instances) continue;

				for (const instance of reservation.Instances) {
					if (instance.InstanceId) {
						instanceIds.push(instance.InstanceId);
					}
				}
			}

			nextToken = response.NextToken;
		} while (nextToken);

		// Check user data for each instance
		for (const instanceId of instanceIds) {
			try {
				const command = new DescribeInstanceAttributeCommand({
					InstanceId: instanceId,
					Attribute: "userData"
				});

				const response = await client.send(command);

				if (!response.UserData?.Value) {
					results.checks.push({
						resourceName: instanceId,
						status: ComplianceStatus.PASS,
						message: "No user data configured"
					});
					continue;
				}

				try {
					const decodedUserData = Buffer.from(response.UserData.Value, "base64").toString("utf-8");
					const hasSensitiveData = containsSensitiveData(decodedUserData);

					results.checks.push({
						resourceName: instanceId,
						status: hasSensitiveData ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
						message: hasSensitiveData ? "User data contains sensitive information" : undefined
					});
				} catch (error) {
					results.checks.push({
						resourceName: instanceId,
						status: ComplianceStatus.ERROR,
						message: `Error decoding user data: ${error instanceof Error ? error.message : String(error)}`
					});
				}
			} catch (error) {
				results.checks.push({
					resourceName: instanceId,
					status: ComplianceStatus.ERROR,
					message: `Error retrieving user data: ${error instanceof Error ? error.message : String(error)}`
				});
			}
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Region Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking EC2 instances: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEc2UserDataSecrets(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data",
	description:
		"EC2 instance user data should not contain sensitive information such as passwords, secrets, or access keys. This control checks if EC2 instances have sensitive data stored in their user data scripts.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.9",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEc2UserDataSecrets
};
