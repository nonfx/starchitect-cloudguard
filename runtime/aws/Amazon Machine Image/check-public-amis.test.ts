// @ts-nocheck
import { EC2Client, DescribeImagesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkPublicAMIs from "./check-public-amis";

const mockEC2Client = mockClient(EC2Client);

const mockPublicAMI = {
	ImageId: "ami-12345678",
	Public: true
};

const mockPrivateAMI = {
	ImageId: "ami-87654321",
	Public: false
};

describe("checkPublicAMIs", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for private AMIs", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockPrivateAMI]
			});

			const result = await checkPublicAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("ami-87654321");
			expect(result.checks[0].resourceArn).toBe("arn:aws:ec2:us-east-1::image/ami-87654321");
		});

		it("should return PASS for multiple private AMIs", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockPrivateAMI, { ...mockPrivateAMI, ImageId: "ami-11111111" }]
			});

			const result = await checkPublicAMIs.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});

		it("should return NOTAPPLICABLE when no AMIs exist", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: []
			});

			const result = await checkPublicAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AMIs found in the account");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for public AMIs", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockPublicAMI]
			});

			const result = await checkPublicAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("AMI is publicly accessible");
		});

		it("should handle mixed public and private AMIs", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockPublicAMI, mockPrivateAMI]
			});

			const result = await checkPublicAMIs.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should handle AMIs without ImageId", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [{ Public: true }]
			});

			const result = await checkPublicAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("AMI found without ImageId");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeImagesCommand).rejects(new Error("API Error"));

			const result = await checkPublicAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking AMIs: API Error");
		});

		it("should handle non-Error exceptions", async () => {
			mockEC2Client.on(DescribeImagesCommand).rejects("String error");

			const result = await checkPublicAMIs.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking AMIs: String error");
		});
	});
});
