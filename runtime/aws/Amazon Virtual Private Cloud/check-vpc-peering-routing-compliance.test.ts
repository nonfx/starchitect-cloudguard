// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	EC2Client,
	DescribeRouteTablesCommand,
	DescribeVpcPeeringConnectionsCommand
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkVpcPeeringRoutingCompliance from "./check-vpc-peering-routing-compliance";

const mockEC2Client = mockClient(EC2Client);

const mockPeeringConnection = {
	VpcPeeringConnectionId: "pcx-12345678",
	Status: { Code: "active" }
};

const mockCompliantRouteTable = {
	RouteTableId: "rtb-compliant",
	Routes: [
		{
			DestinationCidrBlock: "172.31.0.0/24",
			VpcPeeringConnectionId: "pcx-12345678"
		}
	]
};

const mockNonCompliantRouteTable = {
	RouteTableId: "rtb-noncompliant",
	Routes: [
		{
			DestinationCidrBlock: "0.0.0.0/0",
			VpcPeeringConnectionId: "pcx-12345678"
		}
	]
};

describe("checkVpcPeeringRoutingCompliance", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for route tables with least access routes", async () => {
			mockEC2Client
				.on(DescribeVpcPeeringConnectionsCommand)
				.resolves({ VpcPeeringConnections: [mockPeeringConnection] });
			mockEC2Client
				.on(DescribeRouteTablesCommand)
				.resolves({ RouteTables: [mockCompliantRouteTable] });

			const result = await checkVpcPeeringRoutingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("rtb-compliant");
		});

		it("should return NOTAPPLICABLE when no peering connections exist", async () => {
			mockEC2Client
				.on(DescribeVpcPeeringConnectionsCommand)
				.resolves({ VpcPeeringConnections: [] });

			const result = await checkVpcPeeringRoutingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No VPC peering connections found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for route tables with non-least access routes", async () => {
			mockEC2Client
				.on(DescribeVpcPeeringConnectionsCommand)
				.resolves({ VpcPeeringConnections: [mockPeeringConnection] });
			mockEC2Client
				.on(DescribeRouteTablesCommand)
				.resolves({ RouteTables: [mockNonCompliantRouteTable] });

			const result = await checkVpcPeeringRoutingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Route table contains non-least access or overlapping routes for VPC peering"
			);
		});

		it("should handle mixed compliant and non-compliant route tables", async () => {
			mockEC2Client
				.on(DescribeVpcPeeringConnectionsCommand)
				.resolves({ VpcPeeringConnections: [mockPeeringConnection] });
			mockEC2Client
				.on(DescribeRouteTablesCommand)
				.resolves({ RouteTables: [mockCompliantRouteTable, mockNonCompliantRouteTable] });

			const result = await checkVpcPeeringRoutingCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockEC2Client.on(DescribeVpcPeeringConnectionsCommand).rejects(new Error("API Error"));

			const result = await checkVpcPeeringRoutingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking VPC peering routes");
		});

		it("should return NOTAPPLICABLE when no route tables exist", async () => {
			mockEC2Client
				.on(DescribeVpcPeeringConnectionsCommand)
				.resolves({ VpcPeeringConnections: [mockPeeringConnection] });
			mockEC2Client.on(DescribeRouteTablesCommand).resolves({ RouteTables: [] });

			const result = await checkVpcPeeringRoutingCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No route tables found");
		});
	});
});
