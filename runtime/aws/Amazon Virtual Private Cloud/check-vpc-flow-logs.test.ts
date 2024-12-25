import { EC2Client, DescribeVpcsCommand, DescribeFlowLogsCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkVpcFlowLogsCompliance from "./check-vpc-flow-logs";

const mockEC2Client = mockClient(EC2Client);

const mockVpc = {
	VpcId: "vpc-12345678",
	State: "available",
	CidrBlock: "10.0.0.0/16"
};

const mockFlowLog = {
	FlowLogId: "fl-12345678",
	ResourceId: "vpc-12345678",
	FlowLogStatus: "ACTIVE",
	TrafficType: "ALL"
};

describe("checkVpcFlowLogsCompliance", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when VPC has active flow logs capturing all traffic", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [mockVpc] });
			mockEC2Client.on(DescribeFlowLogsCommand).resolves({ FlowLogs: [mockFlowLog] });

			const result = await checkVpcFlowLogsCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("vpc-12345678");
		});

		it("should return NOTAPPLICABLE when no VPCs exist", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [] });

			const result = await checkVpcFlowLogsCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No VPCs found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when VPC has no flow logs", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [mockVpc] });
			mockEC2Client.on(DescribeFlowLogsCommand).resolves({ FlowLogs: [] });

			const result = await checkVpcFlowLogsCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("VPC does not have any flow logs enabled");
		});

		it("should return FAIL when flow logs exist but are not active", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [mockVpc] });
			mockEC2Client.on(DescribeFlowLogsCommand).resolves({
				FlowLogs: [
					{
						...mockFlowLog,
						FlowLogStatus: "INACTIVE"
					}
				]
			});

			const result = await checkVpcFlowLogsCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("VPC does not have any active flow logs");
		});

		it("should return FAIL when flow logs don't capture all traffic", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({ Vpcs: [mockVpc] });
			mockEC2Client.on(DescribeFlowLogsCommand).resolves({
				FlowLogs: [
					{
						...mockFlowLog,
						TrafficType: "REJECT"
					}
				]
			});

			const result = await checkVpcFlowLogsCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("VPC flow logs do not capture all traffic types");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when DescribeVpcs fails", async () => {
			mockEC2Client.on(DescribeVpcsCommand).rejects(new Error("API Error"));

			const result = await checkVpcFlowLogsCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking VPC flow logs: API Error");
		});

		it("should return ERROR for VPC without VpcId", async () => {
			mockEC2Client
				.on(DescribeVpcsCommand)
				.resolves({ Vpcs: [{ State: "available" }] })
				.on(DescribeFlowLogsCommand)
				.resolves({ FlowLogs: [] });

			const result = await checkVpcFlowLogsCompliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("VPC found without VPC ID");
		});

		it("should handle multiple VPCs with mixed compliance", async () => {
			mockEC2Client.on(DescribeVpcsCommand).resolves({
				Vpcs: [mockVpc, { ...mockVpc, VpcId: "vpc-87654321" }]
			});
			mockEC2Client.on(DescribeFlowLogsCommand).resolves({
				FlowLogs: [
					mockFlowLog,
					{
						FlowLogId: "fl-87654321",
						ResourceId: "vpc-87654321",
						FlowLogStatus: "INACTIVE",
						TrafficType: "ALL"
					}
				]
			});

			const result = await checkVpcFlowLogsCompliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
