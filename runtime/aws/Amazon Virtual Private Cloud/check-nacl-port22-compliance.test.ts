import { EC2Client, DescribeNetworkAclsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkNaclPort22Compliance from "./check-nacl-port22-compliance";

const mockEC2Client = mockClient(EC2Client);

const mockCompliantNacl = {
	NetworkAclId: "acl-compliant",
	Entries: [
		{
			RuleNumber: 100,
			Protocol: "tcp",
			RuleAction: "deny",
			CidrBlock: "0.0.0.0/0",
			Egress: false,
			PortRange: { From: 22, To: 22 }
		},
		{
			RuleNumber: 200,
			Protocol: "tcp",
			RuleAction: "allow",
			CidrBlock: "10.0.0.0/8",
			Egress: false,
			PortRange: { From: 22, To: 22 }
		}
	]
};

const mockNonCompliantNacl = {
	NetworkAclId: "acl-non-compliant",
	Entries: [
		{
			RuleNumber: 100,
			Protocol: "tcp",
			RuleAction: "allow",
			CidrBlock: "0.0.0.0/0",
			Egress: false,
			PortRange: { From: 22, To: 22 }
		}
	]
};

const mockAllPortsNacl = {
	NetworkAclId: "acl-all-ports",
	Entries: [
		{
			RuleNumber: 100,
			Protocol: "-1",
			RuleAction: "allow",
			CidrBlock: "0.0.0.0/0",
			Egress: false
		}
	]
};

describe("checkNaclPort22Compliance", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for NACL with denied port 22 access", async () => {
			mockEC2Client.on(DescribeNetworkAclsCommand).resolves({
				NetworkAcls: [mockCompliantNacl]
			});

			const result = await checkNaclPort22Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("acl-compliant");
		});

		it("should return NOTAPPLICABLE when no NACLs exist", async () => {
			mockEC2Client.on(DescribeNetworkAclsCommand).resolves({
				NetworkAcls: []
			});

			const result = await checkNaclPort22Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Network ACLs found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for NACL allowing port 22 from 0.0.0.0/0", async () => {
			mockEC2Client.on(DescribeNetworkAclsCommand).resolves({
				NetworkAcls: [mockNonCompliantNacl]
			});

			const result = await checkNaclPort22Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"NACL allows unrestricted inbound access to port 22 from 0.0.0.0/0"
			);
		});

		it("should return FAIL for NACL allowing all ports from 0.0.0.0/0", async () => {
			mockEC2Client.on(DescribeNetworkAclsCommand).resolves({
				NetworkAcls: [mockAllPortsNacl]
			});

			const result = await checkNaclPort22Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle multiple NACLs with mixed compliance", async () => {
			mockEC2Client.on(DescribeNetworkAclsCommand).resolves({
				NetworkAcls: [mockCompliantNacl, mockNonCompliantNacl, mockAllPortsNacl]
			});

			const result = await checkNaclPort22Compliance.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeNetworkAclsCommand).rejects(new Error("API Error"));

			const result = await checkNaclPort22Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking NACLs: API Error");
		});

		it("should handle NACL without ID", async () => {
			mockEC2Client.on(DescribeNetworkAclsCommand).resolves({
				NetworkAcls: [{ Entries: [] }]
			});

			const result = await checkNaclPort22Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("NACL found without ID");
		});
	});
});
