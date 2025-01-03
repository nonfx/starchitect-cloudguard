// @ts-nocheck
import { EC2Client, DescribeImagesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAmiEncryption from "./check-ami-encryption";

const mockEC2Client = mockClient(EC2Client);

const mockEncryptedAMI = {
    ImageId: "ami-12345678",
    BlockDeviceMappings: [
        {
            Ebs: {
                Encrypted: true,
                SnapshotId: "snap-12345"
            }
        }
    ]
};

const mockUnencryptedAMI = {
    ImageId: "ami-87654321",
    BlockDeviceMappings: [
        {
            Ebs: {
                Encrypted: false,
                SnapshotId: "snap-67890"
            }
        }
    ]
};

const mockMixedEncryptionAMI = {
    ImageId: "ami-11223344",
    BlockDeviceMappings: [
        {
            Ebs: {
                Encrypted: true,
                SnapshotId: "snap-11111"
            }
        },
        {
            Ebs: {
                Encrypted: false,
                SnapshotId: "snap-22222"
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
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe(mockEncryptedAMI.ImageId);
            expect(result.checks[0].resourceArn).toBe(`arn:aws:ec2:us-east-1::image/${mockEncryptedAMI.ImageId}`);
        });

        it("should return NOTAPPLICABLE when no AMIs exist", async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: []
            });

            const result = await checkAmiEncryption.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No AMIs found in the account");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when AMI volumes are unencrypted", async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: [mockUnencryptedAMI]
            });

            const result = await checkAmiEncryption.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("AMI contains unencrypted EBS snapshots");
        });

        it("should return FAIL when AMI has mixed encryption", async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: [mockMixedEncryptionAMI]
            });

            const result = await checkAmiEncryption.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("AMI contains unencrypted EBS snapshots");
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
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Error checking AMIs: API Error");
        });

        it("should handle AMIs without ImageId", async () => {
            mockEC2Client.on(DescribeImagesCommand).resolves({
                Images: [{ BlockDeviceMappings: [] }]
            });

            const result = await checkAmiEncryption.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("AMI found without ImageId");
        });
    });
});