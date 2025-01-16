import { KeyspacesClient } from "@aws-sdk/client-keyspaces";
import { getAllKeyspaces } from "../../utils/aws/get-all-keyspaces.js";
import {
	EC2Client,
	DescribeVpcEndpointsCommand,
	DescribeSecurityGroupsCommand,
	DescribeNetworkAclsCommand,
	DescribeSubnetsCommand
} from "@aws-sdk/client-ec2";
import { printSummary, generateSummary } from "../../utils/string-utils.js";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types.js";

async function checkKeyspacesNetworkSecurity(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const keyspacesClient = new KeyspacesClient({ region });
	const ec2Client = new EC2Client({ region });
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

		// Check VPC Endpoints for Keyspaces service
		const endpoints = await ec2Client.send(
			new DescribeVpcEndpointsCommand({
				Filters: [
					{
						Name: "service-name",
						Values: [`com.amazonaws.${region}.cassandra`]
					}
				]
			})
		);

		for (const keyspace of keyspaces) {
			if (!keyspace.keyspaceName) {
				results.checks.push({
					resourceName: "Unknown Keyspace",
					status: ComplianceStatus.ERROR,
					message: "Keyspace found without name"
				});
				continue;
			}

			const endpoint = endpoints.VpcEndpoints?.[0];
			const hasVpcEndpoint = !!endpoint;
			let hasPrivateSubnets = false;
			let hasSecurityGroups = false;
			let hasNetworkAcls = false;

			if (endpoint) {
				// Check Subnets
				if (endpoint.SubnetIds?.length) {
					const subnets = await ec2Client.send(
						new DescribeSubnetsCommand({
							SubnetIds: endpoint.SubnetIds
						})
					);
					hasPrivateSubnets = subnets.Subnets?.some(subnet => !subnet.MapPublicIpOnLaunch) ?? false;
				}

				// Check Security Groups
				const groupIds = endpoint.Groups?.map(g => g.GroupId).filter((id): id is string => !!id);
				if (groupIds?.length) {
					const sgs = await ec2Client.send(
						new DescribeSecurityGroupsCommand({
							GroupIds: groupIds
						})
					);
					hasSecurityGroups =
						sgs.SecurityGroups?.some(
							sg => (sg.IpPermissions?.length ?? 0) > 0 && (sg.IpPermissionsEgress?.length ?? 0) > 0
						) ?? false;
				}

				// Check Network ACLs
				if (endpoint.SubnetIds?.length) {
					const nacls = await ec2Client.send(
						new DescribeNetworkAclsCommand({
							Filters: [
								{
									Name: "association.subnet-id",
									Values: endpoint.SubnetIds
								}
							]
						})
					);
					hasNetworkAcls =
						nacls.NetworkAcls?.some(nacl => (nacl.Entries?.length ?? 0) > 0) ?? false;
				}
			}

			const isSecure = hasVpcEndpoint && hasPrivateSubnets && hasSecurityGroups && hasNetworkAcls;

			results.checks.push({
				resourceName: keyspace.keyspaceName,
				resourceArn: keyspace.resourceArn,
				status: isSecure ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: isSecure ? undefined : "Keyspace is not configured with VPC network security"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "Keyspaces Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking Keyspaces network security: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION;
	const results = await checkKeyspacesNetworkSecurity(region);
	printSummary(generateSummary(results));
}

export default {
	title: "Ensure Network Security is Enabled",
	description:
		"In order to access Amazon Keyspaces the user is required to set specific networking parameters and security measurements without these extra steps they will not be able to access it. Users are required to create or select a virtual private cloud (VPC) and define their inbound and outbound rules accordingly",
	controls: [
		{
			id: "CIS-AWS-Database-Services-Benchmark_v1.0.0_8.2",
			document: "CIS-AWS-Database-Services-Benchmark_v1.0.0"
		}
	],
	severity: "HIGH",
	execute: checkKeyspacesNetworkSecurity,
	serviceName: "Amazon Keyspaces",
	shortServiceName: "keyspaces"
} satisfies RuntimeTest;
