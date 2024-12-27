// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { EC2Client, DescribeImagesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkAmiEncryption from "./aws_ec2_ami_encryption";

const mockEC2Client = mockClient(EC2Client);

const mockEncryptedAMI = {
	ImageId: "ami-123456789",
	BlockDeviceMappings: [
		{
			DeviceName: "/dev/xvda",
			Ebs: {
				Encrypted: true,
				SnapshotId: "snap-123456789"
			}
		}
	]
};

const mockUnencryptedAMI = {
	ImageId: "ami-987654321",
	BlockDeviceMappings: [
		{
			DeviceName: "/dev/xvda",
			Ebs: {
				Encrypted: false,
				SnapshotId: "snap-987654321"
			}
		}
	]
};

const mockMixedEncryptionAMI = {
	ImageId: "ami-mixed123",
	BlockDeviceMappings: [
		{
			DeviceName: "/dev/xvda",
			Ebs: {
				Encrypted: true,
				SnapshotId: "snap-111111"
			}
		},
		{
			DeviceName: "/dev/xvdb",
			Ebs: {
				Encrypted: false,
				SnapshotId: "snap-222222"
			}
		}
	]
};

describe("checkAmiEncryption", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all AMI volumes are encrypted", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockEncryptedAMI]
			});

			const result = await checkAmiEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("ami-123456789");
		});

		it("should return NOTAPPLICABLE when no AMIs exist", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: []
			});

			const result = await checkAmiEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No AMIs found in the account");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when AMI has unencrypted volumes", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockUnencryptedAMI]
			});

			const result = await checkAmiEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("AMI contains unencrypted EBS volumes");
		});

		it("should return FAIL when AMI has mixed encrypted and unencrypted volumes", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockMixedEncryptionAMI]
			});

			const result = await checkAmiEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("AMI contains unencrypted EBS volumes");
		});

		it("should handle multiple AMIs with different encryption states", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [mockEncryptedAMI, mockUnencryptedAMI, mockMixedEncryptionAMI]
			});

			const result = await checkAmiEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(3);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[2].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeImagesCommand).rejects(new Error("API Error"));

			const result = await checkAmiEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking AMIs: API Error");
		});

		it("should handle AMIs without ImageId", async () => {
			mockEC2Client.on(DescribeImagesCommand).resolves({
				Images: [{ BlockDeviceMappings: [] }]
			});

			const result = await checkAmiEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(1);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("AMI found without Image ID");
		});
	});
});
