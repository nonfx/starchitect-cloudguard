import {
	MemoryDBClient,
	DescribeClustersCommand,
	DescribeUsersCommand,
	DescribeACLsCommand,
	type ACL,
	type User
} from "@aws-sdk/client-memorydb";
import { getAllMemoryDBClusters } from "./get-all-memorydb-clusters.js";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkMemoryDBACLCompliance(region: string = "us-east-1"): Promise<ComplianceReport> {
	const client = new MemoryDBClient({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all MemoryDB clusters
		const clusters = await getAllMemoryDBClusters(client);
		if (clusters.length === 0) {
			results.checks.push({
				resourceName: "No MemoryDB Clusters",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No MemoryDB clusters found in the region"
			});
			return results;
		}

		// Get all ACLs
		const acls = await client.send(new DescribeACLsCommand({}));
		const aclMap = new Map(acls.ACLs?.map((acl: ACL) => [acl.Name, acl]) || []);

		// Get all users
		const users = await client.send(new DescribeUsersCommand({}));
		const userMap = new Map(users.Users?.map((user: User) => [user.Name, user]) || []);

		for (const cluster of clusters) {
			if (!cluster.Name) {
				results.checks.push({
					resourceName: "Unknown Cluster",
					status: ComplianceStatus.ERROR,
					message: "Cluster found without name"
				});
				continue;
			}

			const aclName = cluster.ACLName;
			const acl = aclName ? aclMap.get(aclName) : undefined;

			if (!acl) {
				results.checks.push({
					resourceName: cluster.Name,
					resourceArn: cluster.ARN,
					status: ComplianceStatus.FAIL,
					message: "Cluster does not have an ACL configured"
				});
				continue;
			}

			// Check if ACL has properly configured users
			let hasProperUserConfig = true;
			let userConfigMessage = "";

			for (const userGroup of acl.UserNames || []) {
				const user = userMap.get(userGroup);
				if (!user) continue;

				const authMode = user.Authentication;
				const accessString = user.AccessString;

				if (!authMode || !accessString) {
					hasProperUserConfig = false;
					userConfigMessage = "User missing authentication mode or access string";
					break;
				}

				if (accessString.includes("all")) {
					hasProperUserConfig = false;
					userConfigMessage = "User has overly permissive access string";
					break;
				}

				if (authMode.Type !== "password" && authMode.Type !== "iam") {
					hasProperUserConfig = false;
					userConfigMessage = "User has invalid authentication type";
					break;
				}
			}

			results.checks.push({
				resourceName: cluster.Name,
				resourceArn: cluster.ARN,
				status: hasProperUserConfig ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasProperUserConfig ? undefined : `ACL configuration issue: ${userConfigMessage}`
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "MemoryDB Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking MemoryDB clusters: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION || "ap-southeast-1";
	const results = await checkMemoryDBACLCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	serviceName: "Amazon MemoryDB",
	shortServiceName: "memorydb",
	title: "Ensure MemoryDB ACLs are properly configured",
	description:
		"Ensure that Amazon MemoryDB clusters have ACLs properly configured to control access effectively, including user authentication and access strings.",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_6.3",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkMemoryDBACLCompliance
} satisfies RuntimeTest;
