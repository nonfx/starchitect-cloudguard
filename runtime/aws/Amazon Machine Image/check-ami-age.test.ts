// @ts-nocheck
import { EC2Client, DescribeImagesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAmiAge from "./check-ami-age";

const mockEC2Client = mockClient(EC2Client);

const createMockAmi = (imageId: string, creationDate: Date) => ({
	ImageId: imageId,
	CreationDate: creationDate.toISOString(),
	Name: `test-ami-${imageId}`
});

describe("checkAmiAge", () => {
	beforeEach(() => {
		mockEC2Client.reset();
		jest.useFakeTimers();
		jest.setSystemTime(new Date("2024-01-01"));
	});

	afterEach(() => {
		jest.useRealTimers();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for AMIs newer than 90 days", async () => {
			const newAmi = createMockAmi("ami-123", new Date("2023-12-15"));
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [newAmi]
			});

			const result = await checkAmiAge.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("ami-123");
			expect(result.checks[0].resourceArn).toBe("arn:aws:ec2:us-east-1::image/ami-123");
		});

		it("should handle multiple compliant AMIs", async () => {
			const newAmis = [
				createMockAmi("ami-123", new Date("2023-12-15")),
				createMockAmi("ami-456", new Date("2023-11-15"))
			];
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: newAmis
			});

			const result = await checkAmiAge.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for AMIs older than 90 days", async () => {
			const oldAmi = createMockAmi("ami-789", new Date("2023-09-01"));
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [oldAmi]
			});

			const result = await checkAmiAge.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("AMI is older than 90 days");
		});

		it("should handle mixed compliant and non-compliant AMIs", async () => {
			const mixedAmis = [
				createMockAmi("ami-123", new Date("2023-12-15")),
				createMockAmi("ami-456", new Date("2023-08-01"))
			];
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: mixedAmis
			});

			const result = await checkAmiAge.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		it("should return NOTAPPLICABLE when no AMIs exist", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: []
			});

			const result = await checkAmiAge.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AMIs found in the account");
		});

		it("should handle AMIs with missing required information", async () => {
			const invalidAmi = { ImageId: "ami-invalid" }; // Missing CreationDate
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [invalidAmi]
			});

			const result = await checkAmiAge.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("AMI missing required information");
		});

		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeImagesCommand).rejects(new Error("API Error"));

			const result = await checkAmiAge.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking AMIs: API Error");
		});
	});
});
