import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

// List of high-risk ports that should be restricted
const HIGH_RISK_PORTS = new Set([
	20, 21, 22, 23, 25, 110, 135, 143, 445, 1433, 1434, 3000, 3306, 3389, 4333, 5000, 5432, 5500,
	5601, 8080, 8088, 8888, 9200, 9300
]);

// Check if a port falls within high-risk range
function isHighRiskPort(fromPort: number, toPort: number): boolean {
	for (let port = fromPort; port <= toPort; port++) {
		if (HIGH_RISK_PORTS.has(port)) {
			return true;
		}
	}
	return false;
}

// Check if CIDR is unrestricted (0.0.0.0/0 or ::/0)
function isUnrestrictedCidr(cidr: string): boolean {
	return cidr === "0.0.0.0/0" || cidr === "::/0";
}

async function checkSecurityGroupHighRiskPorts(
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
			if (!sg.GroupId) {
				results.checks.push({
					resourceName: "Unknown Security Group",
					status: ComplianceStatus.ERROR,
					message: "Security group found without ID"
				});
				continue;
			}

			let hasUnrestrictedHighRiskPort = false;
			const violatingPorts: number[] = [];

			// Check inbound rules
			for (const rule of sg.IpPermissions || []) {
				const fromPort = rule.FromPort || 0;
				const toPort = rule.ToPort || 65535;

				if (isHighRiskPort(fromPort, toPort)) {
					// Check IPv4 CIDR ranges
					for (const ipRange of rule.IpRanges || []) {
						if (ipRange.CidrIp && isUnrestrictedCidr(ipRange.CidrIp)) {
							hasUnrestrictedHighRiskPort = true;
							violatingPorts.push(fromPort);
						}
					}

					// Check IPv6 CIDR ranges
					for (const ipv6Range of rule.Ipv6Ranges || []) {
						if (ipv6Range.CidrIpv6 && isUnrestrictedCidr(ipv6Range.CidrIpv6)) {
							hasUnrestrictedHighRiskPort = true;
							violatingPorts.push(fromPort);
						}
					}
				}
			}

			results.checks.push({
				resourceName: sg.GroupId,
				resourceArn: `arn:aws:ec2:${region}:${sg.OwnerId}:security-group/${sg.GroupId}`,
				status: hasUnrestrictedHighRiskPort ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: hasUnrestrictedHighRiskPort
					? `Security group allows unrestricted access to high-risk ports: ${violatingPorts.join(", ")}`
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
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkSecurityGroupHighRiskPorts(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Security groups should not allow unrestricted access to ports with high risk",
	description:
		"This control checks if security groups restrict access to high-risk ports from unrestricted sources.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.19",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkSecurityGroupHighRiskPorts
} satisfies RuntimeTest;
