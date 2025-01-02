// @ts-nocheck
import {
	EC2Client,
	DescribeVolumesCommand,
	GetEbsEncryptionByDefaultCommand
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEbsVolumeEncryption from "./check-ebs-volume-encryption";

const mockEC2Client = mockClient(EC2Client);

describe("checkEbsVolumeEncryption", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when default encryption is enabled and all volumes are encrypted", async () => {
			mockEC2Client.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });

			mockEC2Client.on(DescribeVolumesCommand).resolves({
				Volumes: [
					{ VolumeId: "vol-123", Encrypted: true },
					{ VolumeId: "vol-456", Encrypted: true }
				]
			});

			const result = await checkEbsVolumeEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no volumes exist but default encryption is enabled", async () => {
			mockEC2Client.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });

			mockEC2Client.on(DescribeVolumesCommand).resolves({
				Volumes: []
			});

			const result = await checkEbsVolumeEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EBS volumes found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when default encryption is disabled", async () => {
			mockEC2Client
				.on(GetEbsEncryptionByDefaultCommand)
				.resolves({ EbsEncryptionByDefault: false });

			const result = await checkEbsVolumeEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"EBS encryption by default is not enabled in this region"
			);
		});

		it("should return FAIL for unencrypted volumes", async () => {
			mockEC2Client.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });

			mockEC2Client.on(DescribeVolumesCommand).resolves({
				Volumes: [
					{ VolumeId: "vol-123", Encrypted: false },
					{ VolumeId: "vol-456", Encrypted: true }
				]
			});

			const result = await checkEbsVolumeEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("EBS volume is not encrypted");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when GetEbsEncryptionByDefault fails", async () => {
			mockEC2Client.on(GetEbsEncryptionByDefaultCommand).rejects(new Error("API Error"));

			const result = await checkEbsVolumeEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EBS volumes");
		});

		it("should return ERROR for volumes without VolumeId", async () => {
			mockEC2Client.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });

			mockEC2Client.on(DescribeVolumesCommand).resolves({
				Volumes: [
					{ Encrypted: true }, // Missing VolumeId
					{ VolumeId: "vol-456", Encrypted: true }
				]
			});

			const result = await checkEbsVolumeEncryption.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Volume found without Volume ID");
		});

		it("should return ERROR when DescribeVolumes fails", async () => {
			mockEC2Client.on(GetEbsEncryptionByDefaultCommand).resolves({ EbsEncryptionByDefault: true });

			mockEC2Client.on(DescribeVolumesCommand).rejects(new Error("Failed to describe volumes"));

			const result = await checkEbsVolumeEncryption.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to describe volumes");
		});
	});
});
