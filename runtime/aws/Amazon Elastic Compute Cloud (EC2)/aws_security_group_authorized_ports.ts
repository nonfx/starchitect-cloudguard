import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "~codegen/utils/stringUtils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "~runtime/types";

// Default authorized ports
const AUTHORIZED_TCP_PORTS = [80, 443];

async function checkSecurityGroupAuthorizedPorts(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all security groups
		const response = await client.send(new DescribeSecurityGroupsCommand({}));

		if (!response.SecurityGroups || response.SecurityGroups.length === 0) {
			results.checks = [
				{
					resourceName: "No Security Groups",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No security groups found in the region"
				}
			];
			return results;
		}

		for (const sg of response.SecurityGroups) {
			if (!sg.GroupId || !sg.GroupName) {
				results.checks.push({
					resourceName: "Unknown Security Group",
					status: ComplianceStatus.ERROR,
					message: "Security group found without ID or name"
				});
				continue;
			}

			let hasUnauthorizedAccess = false;
			const unauthorizedPorts: number[] = [];

			// Check ingress rules
			for (const rule of sg.IpPermissions || []) {
				// Check only TCP rules
				if (rule.IpProtocol === "tcp") {
					// Check if rule has unrestricted access (0.0.0.0/0)
					const hasUnrestrictedAccess = (rule.IpRanges || []).some(
						ipRange => ipRange.CidrIp === "0.0.0.0/0"
					);

					if (hasUnrestrictedAccess) {
						// Check if port is unauthorized
						const fromPort = rule.FromPort || 0;
						if (!AUTHORIZED_TCP_PORTS.includes(fromPort)) {
							hasUnauthorizedAccess = true;
							unauthorizedPorts.push(fromPort);
						}
					}
				}
			}

			results.checks.push({
				resourceName: sg.GroupName,
				resourceArn: `arn:aws:ec2:${region}:${sg.OwnerId}:security-group/${sg.GroupId}`,
				status: hasUnauthorizedAccess ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: hasUnauthorizedAccess
					? `Security group allows unrestricted access on unauthorized ports: ${unauthorizedPorts.join(
							", "
						)}`
					: undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "Security Groups Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking security groups: ${error instanceof Error ? error.message : String(error)}`
			}
		];
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkSecurityGroupAuthorizedPorts(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Security groups should only allow unrestricted incoming traffic for authorized ports",
	description:
		"Security groups should only allow unrestricted incoming traffic on authorized ports to protect network security.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.18",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkSecurityGroupAuthorizedPorts
} satisfies RuntimeTest;
