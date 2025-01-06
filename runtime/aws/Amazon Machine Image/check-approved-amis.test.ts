// @ts-nocheck
import { EC2Client, DescribeImagesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkApprovedAMIs from "./check-approved-amis";

const mockEC2Client = mockClient(EC2Client);

const mockApprovedAMI = {
	ImageId: "ami-example1",
	Name: "approved-ami-1",
	OwnerId: "123456789012"
};

const mockUnapprovedAMI = {
	ImageId: "ami-unapproved",
	Name: "unapproved-ami",
	OwnerId: "123456789012"
};

describe("checkApprovedAMIs", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for approved AMIs", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockApprovedAMI]
			});

			const result = await checkApprovedAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("approved-ami-1");
			expect(result.checks[0].resourceArn).toBe("arn:aws:ec2:us-east-1::image/ami-example1");
		});

		it("should return NOTAPPLICABLE when no AMIs exist", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: []
			});

			const result = await checkApprovedAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AMIs found in the account");
		});

		it("should handle multiple approved AMIs", async () => {
			const multipleApprovedAMIs = [
				mockApprovedAMI,
				{
					ImageId: "ami-example2",
					Name: "approved-ami-2",
					OwnerId: "123456789012"
				}
			];

			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: multipleApprovedAMIs
			});

			const result = await checkApprovedAMIs.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for unapproved AMIs", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockUnapprovedAMI]
			});

			const result = await checkApprovedAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("AMI is not in the approved list");
		});

		it("should handle mixed approved and unapproved AMIs", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockApprovedAMI, mockUnapprovedAMI]
			});

			const result = await checkApprovedAMIs.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle AMIs without ImageId", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [{ Name: "invalid-ami" }]
			});

			const result = await checkApprovedAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("AMI found without ImageId");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeImagesCommand).rejects(new Error("API Error"));

			const result = await checkApprovedAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking AMIs: API Error");
		});

		it("should handle undefined Images response", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({});

			const result = await checkApprovedAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AMIs found in the account");
		});
	});
});
