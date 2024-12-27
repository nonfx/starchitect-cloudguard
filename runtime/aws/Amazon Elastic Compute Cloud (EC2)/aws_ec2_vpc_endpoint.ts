import {
	EC2Client,
	DescribeInstancesCommand,
	DescribeVpcEndpointsCommand
} from "@aws-sdk/client-ec2";

import { printSummary, generateSummary } from "../../utils/string-utils";
import { ComplianceStatus, type ComplianceReport, type RuntimeTest } from "../../types";

async function checkEc2VpcEndpointCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: []
	};

	try {
		// Get all EC2 instances and their VPC IDs
		const instancesResponse = await client.send(new DescribeInstancesCommand({}));

		if (!instancesResponse.Reservations || instancesResponse.Reservations.length === 0) {
			results.checks.push({
				resourceName: "No EC2 Instances",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No EC2 instances found in the region"
			});
			return results;
		}

		// Create a map of VPC IDs to instances
		const vpcInstances = new Map<string, string[]>();

		for (const reservation of instancesResponse.Reservations) {
			for (const instance of reservation.Instances || []) {
				if (instance.VpcId && instance.InstanceId) {
					const instances = vpcInstances.get(instance.VpcId) || [];
					instances.push(instance.InstanceId);
					vpcInstances.set(instance.VpcId, instances);
				}
			}
		}

		// Get all VPC endpoints
		const endpointsResponse = await client.send(new DescribeVpcEndpointsCommand({}));

		// Create a map of VPC IDs to EC2 endpoints
		const vpcEndpoints = new Set<string>();

		for (const endpoint of endpointsResponse.VpcEndpoints || []) {
			if (
				endpoint.VpcId &&
				endpoint.ServiceName?.includes(".ec2") &&
				endpoint.VpcEndpointType === "Interface"
			) {
				vpcEndpoints.add(endpoint.VpcId);
			}
		}

		// Check compliance for each VPC with instances
		for (const [vpcId, instanceIds] of vpcInstances.entries()) {
			const hasEndpoint = vpcEndpoints.has(vpcId);

			results.checks.push({
				resourceName: `VPC ${vpcId}`,
				status: hasEndpoint ? ComplianceStatus.PASS : ComplianceStatus.FAIL,
				message: hasEndpoint
					? undefined
					: `VPC contains ${instanceIds.length} EC2 instance(s) but no EC2 VPC endpoint`
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "EC2 VPC Endpoint Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking EC2 VPC endpoints: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (import.meta.main) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkEc2VpcEndpointCompliance(region);
	printSummary(generateSummary(results));
}

export default {
	title:
		"Amazon EC2 should be configured to use VPC endpoints that are created for the Amazon EC2 service",
	description:
		"This control checks if VPC endpoints are created for the EC2 service in VPCs that contain EC2 instances. The control fails if a VPC containing EC2 instances does not have an EC2 VPC endpoint.",
	controls: [
		{
			id: "AWS-Foundational-Security-Best-Practices_v1.0.0_EC2.10",
			document: "AWS-Foundational-Security-Best-Practices_v1.0.0"
		}
	],
	severity: "MEDIUM",
	execute: checkEc2VpcEndpointCompliance
} satisfies RuntimeTest;
