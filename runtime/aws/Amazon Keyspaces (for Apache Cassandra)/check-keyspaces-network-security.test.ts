//@ts-nocheck
import { KeyspacesClient, ListKeyspacesCommand } from "@aws-sdk/client-keyspaces";
import {
	EC2Client,
	DescribeVpcEndpointsCommand,
	DescribeSecurityGroupsCommand,
	DescribeNetworkAclsCommand,
	DescribeSubnetsCommand
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkKeyspacesNetworkSecurity from "./check-keyspaces-network-security";

const mockKeyspacesClient = mockClient(KeyspacesClient);
const mockEC2Client = mockClient(EC2Client);

const mockKeyspace = {
	keyspaceName: "test-keyspace-1",
	resourceArn: "arn:aws:cassandra:us-east-1:123456789012:keyspace/test-keyspace-1"
};

const mockVpcEndpoint = {
	VpcEndpointId: "vpce-123456",
	SubnetIds: ["subnet-123", "subnet-456"],
	Groups: [{ GroupId: "sg-123" }]
};

const mockSubnet = {
	SubnetId: "subnet-123",
	MapPublicIpOnLaunch: false
};

const mockSecurityGroup = {
	GroupId: "sg-123",
	IpPermissions: [{ FromPort: 9142 }],
	IpPermissionsEgress: [{ FromPort: -1 }]
};

const mockNetworkAcl = {
	NetworkAclId: "acl-123",
	Entries: [{ RuleNumber: 100 }]
};

describe("checkKeyspacesNetworkSecurity", () => {
	beforeEach(() => {
		mockKeyspacesClient.reset();
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all security configurations are present", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).resolves({
				keyspaces: [mockKeyspace]
			});

			mockEC2Client
				.on(DescribeVpcEndpointsCommand)
				.resolves({ VpcEndpoints: [mockVpcEndpoint] })
				.on(DescribeSubnetsCommand)
				.resolves({ Subnets: [mockSubnet] })
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: [mockSecurityGroup] })
				.on(DescribeNetworkAclsCommand)
				.resolves({ NetworkAcls: [mockNetworkAcl] });

			const result = await checkKeyspacesNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-keyspace-1");
		});

		it("should return NOTAPPLICABLE when no keyspaces exist", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).resolves({
				keyspaces: []
			});

			const result = await checkKeyspacesNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Keyspaces found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no VPC endpoint exists", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).resolves({
				keyspaces: [mockKeyspace]
			});

			mockEC2Client.on(DescribeVpcEndpointsCommand).resolves({
				VpcEndpoints: []
			});

			const result = await checkKeyspacesNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Keyspace is not configured with VPC network security");
		});

		it("should return FAIL when missing private subnets", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).resolves({
				keyspaces: [mockKeyspace]
			});

			mockEC2Client
				.on(DescribeVpcEndpointsCommand)
				.resolves({ VpcEndpoints: [mockVpcEndpoint] })
				.on(DescribeSubnetsCommand)
				.resolves({ Subnets: [{ ...mockSubnet, MapPublicIpOnLaunch: true }] })
				.on(DescribeSecurityGroupsCommand)
				.resolves({ SecurityGroups: [mockSecurityGroup] })
				.on(DescribeNetworkAclsCommand)
				.resolves({ NetworkAcls: [mockNetworkAcl] });

			const result = await checkKeyspacesNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle keyspace without name", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).resolves({
				keyspaces: [{ resourceArn: "arn:aws:cassandra:test" }]
			});

			const result = await checkKeyspacesNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Keyspace found without name");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API calls fail", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).rejects(new Error("API Error"));

			const result = await checkKeyspacesNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking Keyspaces network security");
		});

		it("should handle EC2 API failures gracefully", async () => {
			mockKeyspacesClient.on(ListKeyspacesCommand).resolves({
				keyspaces: [mockKeyspace]
			});

			mockEC2Client.on(DescribeVpcEndpointsCommand).rejects(new Error("EC2 API Error"));

			const result = await checkKeyspacesNetworkSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		});
	});
});
