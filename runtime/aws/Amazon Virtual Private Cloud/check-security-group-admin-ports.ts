import { EC2Client, DescribeSecurityGroupsCommand } from "@aws-sdk/client-ec2";

import {
	printSummary,
	generateSummary,
	type ComplianceReport,
	ComplianceStatus
} from "@codegen/utils/stringUtils";

const ADMIN_PORTS = [22, 3389];

async function checkSecurityGroupAdminPorts(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: [],
		metadoc: {
			title:
				"Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports such as 22 and 3389 (Remote Desktop Protocol)",
			description:
				"Security groups provide stateful filtering of ingress and egress network traffic to AWS resources. It is recommended that no security group allows unrestricted ingress access to remote server administration ports such as 22 & 3389",
			controls: [
				{
					id: "CIS-AWS-Foundations-Benchmark_v3.0.0_5.2",
					document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
				},
				{
					id: "CIS-AWS-Foundations-Benchmark_v3.0.0_5.3",
					document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
				}
			]
		}
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

			let hasViolation = false;
			let violatingPorts: number[] = [];

			// Check ingress rules
			for (const rule of sg.IpPermissions || []) {
				const fromPort = rule.FromPort || 0;
				const toPort = rule.ToPort || 65535;

				// Check if any admin ports are in range
				const hasAdminPorts = ADMIN_PORTS.some(port => port >= fromPort && port <= toPort);

				if (hasAdminPorts) {
					// Check for 0.0.0.0/0 or ::/0
					const hasOpenIpv4 = (rule.IpRanges || []).some(range => range.CidrIp === "0.0.0.0/0");
					const hasOpenIpv6 = (rule.Ipv6Ranges || []).some(range => range.CidrIpv6 === "::/0");

					if (hasOpenIpv4 || hasOpenIpv6) {
						hasViolation = true;
						ADMIN_PORTS.forEach(port => {
							if (port >= fromPort && port <= toPort) {
								violatingPorts.push(port);
							}
						});
					}
				}
			}

			results.checks.push({
				resourceName: sg.GroupId,
				resourceArn: `arn:aws:ec2:${region}:${sg.OwnerId}:security-group/${sg.GroupId}`,
				status: hasViolation ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: hasViolation
					? `Security group allows unrestricted access (0.0.0.0/0) to admin ports: ${violatingPorts.join(", ")}`
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

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkSecurityGroupAdminPorts(region);
	printSummary(generateSummary(results));
}

export default checkSecurityGroupAdminPorts;
