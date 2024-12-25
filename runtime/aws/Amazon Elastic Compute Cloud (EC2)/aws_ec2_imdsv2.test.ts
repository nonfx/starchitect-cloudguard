import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkEc2ImdsV2Compliance from "./aws_ec2_imdsv2";

const mockEC2Client = mockClient(EC2Client);

const mockCompliantInstance = {
	InstanceId: "i-1234567890compliant",
	MetadataOptions: {
		HttpEndpoint: "enabled",
		HttpTokens: "required"
	}
};

const mockNonCompliantInstance = {
	InstanceId: "i-1234567890noncompliant",
	MetadataOptions: {
		HttpEndpoint: "enabled",
		HttpTokens: "optional"
	}
};

describe("checkEc2ImdsV2Compliance", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for instances with IMDSv2 required", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockCompliantInstance]
					}
				]
			});

			const result = await checkEc2ImdsV2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("i-1234567890compliant");
		});

		it("should handle multiple compliant instances", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockCompliantInstance, mockCompliantInstance]
					}
				]
			});

			const result = await checkEc2ImdsV2Compliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for instances with IMDSv2 optional", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockNonCompliantInstance]
					}
				]
			});

			const result = await checkEc2ImdsV2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Instance metadata service is not configured to require IMDSv2"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockCompliantInstance, mockNonCompliantInstance]
					}
				]
			});

			const result = await checkEc2ImdsV2Compliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should return ERROR for instances with missing metadata options", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							{
								InstanceId: "i-nometa"
							}
						]
					}
				]
			});

			const result = await checkEc2ImdsV2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to determine metadata options");
		});
	});

	describe("Edge Cases", () => {
		it("should return NOTAPPLICABLE when no instances exist", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: []
			});

			const result = await checkEc2ImdsV2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EC2 instances found in the region");
		});

		it("should handle pagination correctly", async () => {
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolvesOnce({
					Reservations: [{ Instances: [mockCompliantInstance] }],
					NextToken: "token1"
				})
				.resolvesOnce({
					Reservations: [{ Instances: [mockNonCompliantInstance] }]
				});

			const result = await checkEc2ImdsV2Compliance.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
		});

		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeInstancesCommand).rejects(new Error("API Error"));

			const result = await checkEc2ImdsV2Compliance.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EC2 instances: API Error");
		});
	});
});
