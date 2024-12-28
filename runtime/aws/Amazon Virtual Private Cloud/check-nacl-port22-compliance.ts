import { DescribeNetworkAclsCommand, EC2Client } from "@aws-sdk/client-ec2";
import { generateSummary, printSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

interface NaclEntry {
	RuleNumber: number;
	Protocol: string;
	RuleAction: string;
	CidrBlock?: string;
	PortRange?: {
		From?: number;
		To?: number;
	};
}

function isPort22Rule(entry: NaclEntry): boolean {
	return (
		entry.PortRange?.From === 22 ||
		(entry.PortRange?.From === undefined && entry.PortRange?.To === undefined) // All ports
	);
}

function hasUnsafePort22Access(entries: NaclEntry[]): boolean {
	// Sort entries by rule number (lower numbers have higher priority)
	const sortedEntries = [...entries].sort((a, b) => a.RuleNumber - b.RuleNumber);

	// Find first matching rule for port 22
	for (const entry of sortedEntries) {
		if (
			isPort22Rule(entry) &&
			entry.CidrBlock === "0.0.0.0/0" &&
			(entry.Protocol === "-1" || entry.Protocol === "tcp")
		) {
			return entry.RuleAction === "allow";
		}
	}

	return false;
}

async function checkNaclPort22Compliance(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		const response = await client.send(new DescribeNetworkAclsCommand({}));

		if (!response.NetworkAcls || response.NetworkAcls.length === 0) {
			results.checks = [
				{
					resourceName: "No NACLs",
					status: ComplianceStatus.NOTAPPLICABLE,
					message: "No Network ACLs found in the region"
				}
			];
			return results;
		}

		for (const nacl of response.NetworkAcls) {
			if (!nacl.NetworkAclId) {
				results.checks.push({
					resourceName: "Unknown NACL",
					status: ComplianceStatus.ERROR,
					message: "NACL found without ID"
				});
				continue;
			}

			const entries = (nacl.Entries?.filter(entry => entry.Egress === false) || []).map(entry => ({
				RuleNumber: entry.RuleNumber || 0,
				Protocol: entry.Protocol || "-1",
				RuleAction: entry.RuleAction || "deny",
				CidrBlock: entry.CidrBlock,
				PortRange: entry.PortRange
			}));
			const hasUnsafeAccess = hasUnsafePort22Access(entries);

			results.checks.push({
				resourceName: nacl.NetworkAclId,
				status: hasUnsafeAccess ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
				message: hasUnsafeAccess
					? "NACL allows unrestricted inbound access to port 22 from 0.0.0.0/0"
					: undefined
			});
		}
	} catch (error) {
		results.checks = [
			{
				resourceName: "NACL Check",
				status: ComplianceStatus.ERROR,
				message: `Error checking NACLs: ${error instanceof Error ? error.message : String(error)}`
			}
		];
		return results;
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkNaclPort22Compliance(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration port 22",
	description:
		"The Network Access Control List (NACL) function provide stateless filtering of ingress and egress network traffic to AWS resources. It is recommended that no NACL allows unrestricted ingress access to remote server administration port 22",
	controls: [
		{
			id: "CIS-AWS-Foundations-Benchmark_v3.0.0_5.1",
			document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkNaclPort22Compliance
} satisfies RuntimeTest;
