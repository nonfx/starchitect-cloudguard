import {
	EC2Client,
	DescribeRouteTablesCommand,
	DescribeVpcPeeringConnectionsCommand
} from "@aws-sdk/client-ec2";

import {
	printSummary,
	generateSummary,
	type ComplianceReport,
	ComplianceStatus
} from "@codegen/utils/stringUtils";

function isLeastAccessRoute(cidrBlock: string | undefined): boolean {
	if (!cidrBlock) return false;

	// Split CIDR into IP and prefix length
	const parts = cidrBlock.split("/");
	if (parts.length !== 2) return false;

	const prefixLength = parseInt(parts[1] || "0");
	// Check if prefix length is at least /24 and not /32
	return prefixLength >= 24 && prefixLength < 32;
}

interface RouteInfo {
	network: number;
	prefix: number;
	mask: number;
}

function hasOverlappingRoutes(routes: { DestinationCidrBlock?: string }[]): boolean {
	const peeringRoutes: RouteInfo[] = [];

	for (const route of routes) {
		if (!route.DestinationCidrBlock) continue;

		const [ipPart, prefixPart] = route.DestinationCidrBlock.split("/");
		if (!ipPart || !prefixPart) continue;

		const parts = ipPart.split(".").map(Number);
		if (parts.length !== 4) continue;

		const prefixNum = parseInt(prefixPart);
		if (isNaN(prefixNum)) continue;

		// Calculate network address
		const networkBits = parts.reduce((acc, octet) => (acc << 8) + octet, 0) >>> 0;
		const mask = ~((1 << (32 - prefixNum)) - 1) >>> 0;
		const network = networkBits & mask;

		peeringRoutes.push({
			network,
			prefix: prefixNum,
			mask
		});
	}

	// Check each pair of routes for overlap
	for (const routeA of peeringRoutes) {
		for (const routeB of peeringRoutes) {
			if (routeA === routeB) continue;
			// Two networks overlap if their network addresses match after applying both masks
			if ((routeA.network & routeB.mask) === (routeB.network & routeA.mask)) {
				return true;
			}
		}
	}

	return false;
}

async function checkVpcPeeringRoutingCompliance(
	region: string = "us-east-1"
): Promise<ComplianceReport> {
	const client = new EC2Client({ region });
	const results: ComplianceReport = {
		checks: [],
		metadoc: {
			title: 'Ensure routing tables for VPC peering are "least access"',
			description:
				"Once a VPC peering connection is established, routing tables must be updated to establish any connections between the peered VPCs. These routes can be as specific as desired - even peering a VPC to only a single host on the other side of the connection.",
			controls: [
				{
					id: "CIS-AWS-Foundations-Benchmark_v3.0.0_5.5",
					document: "CIS-AWS-Foundations-Benchmark_v3.0.0"
				}
			]
		}
	};

	try {
		// First check if there are any VPC peering connections
		const peeringConnections = await client.send(new DescribeVpcPeeringConnectionsCommand({}));

		if (!peeringConnections.VpcPeeringConnections?.length) {
			results.checks.push({
				resourceName: "VPC Peering",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No VPC peering connections found"
			});
			return results;
		}

		// Get all route tables
		const routeTables = await client.send(new DescribeRouteTablesCommand({}));

		if (!routeTables.RouteTables?.length) {
			results.checks.push({
				resourceName: "Route Tables",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No route tables found"
			});
			return results;
		}

		// Check each route table
		for (const routeTable of routeTables.RouteTables) {
			if (!routeTable.RouteTableId) continue;

			let hasNonCompliantRoutes = false;
			let hasPeeringRoutes = false;
			const peeringRoutes = routeTable.Routes?.filter(route => route.VpcPeeringConnectionId) || [];

			// Check for overlapping routes first
			if (peeringRoutes.length > 0) {
				hasPeeringRoutes = true;
				if (hasOverlappingRoutes(peeringRoutes)) {
					hasNonCompliantRoutes = true;
				} else {
					// Check each route's CIDR if no overlaps
					for (const route of peeringRoutes) {
						if (!isLeastAccessRoute(route.DestinationCidrBlock)) {
							hasNonCompliantRoutes = true;
							break;
						}
					}
				}
			}

			// Only evaluate route tables that have peering routes
			if (hasPeeringRoutes) {
				results.checks.push({
					resourceName: routeTable.RouteTableId,
					status: hasNonCompliantRoutes ? ComplianceStatus.FAIL : ComplianceStatus.PASS,
					message: hasNonCompliantRoutes
						? "Route table contains non-least access or overlapping routes for VPC peering"
						: undefined
				});
			}
		}

		// If no route tables with peering routes were found
		if (results.checks.length === 0) {
			results.checks.push({
				resourceName: "Route Tables",
				status: ComplianceStatus.NOTAPPLICABLE,
				message: "No route tables with VPC peering routes found"
			});
		}
	} catch (error) {
		results.checks.push({
			resourceName: "VPC Peering Routes Check",
			status: ComplianceStatus.ERROR,
			message: `Error checking VPC peering routes: ${error instanceof Error ? error.message : String(error)}`
		});
	}

	return results;
}

if (require.main === module) {
	const region = process.env.AWS_REGION ?? "ap-southeast-1";
	const results = await checkVpcPeeringRoutingCompliance(region);
	printSummary(generateSummary(results));
}

export default checkVpcPeeringRoutingCompliance;
