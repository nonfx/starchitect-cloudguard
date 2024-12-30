// @ts-nocheck
import { EC2Client, DescribeNetworkInterfacesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkUnusedENIs from "./check-unused-enis";

const mockEC2Client = mockClient(EC2Client);

const mockAttachedENI = {
    NetworkInterfaceId: "eni-123456789",
    Attachment: {
        AttachmentId: "eni-attach-123",
        InstanceId: "i-1234567890"
    }
};

const mockUnattachedENI = {
    NetworkInterfaceId: "eni-987654321"
};

describe("checkUnusedENIs", () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for attached ENIs", async () => {
            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({
                NetworkInterfaces: [mockAttachedENI]
            });

            const result = await checkUnusedENIs("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("eni-123456789");
        });

        it("should handle multiple attached ENIs", async () => {
            const multipleAttachedENIs = [
                mockAttachedENI,
                {
                    NetworkInterfaceId: "eni-abcdef",
                    Attachment: { AttachmentId: "eni-attach-456" }
                }
            ];

            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({
                NetworkInterfaces: multipleAttachedENIs
            });

            const result = await checkUnusedENIs("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for unattached ENIs", async () => {
            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({
                NetworkInterfaces: [mockUnattachedENI]
            });

            const result = await checkUnusedENIs("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("ENI is not attached to any instance");
        });

        it("should handle mixed attached and unattached ENIs", async () => {
            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({
                NetworkInterfaces: [mockAttachedENI, mockUnattachedENI]
            });

            const result = await checkUnusedENIs("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should return ERROR for ENIs without NetworkInterfaceId", async () => {
            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({
                NetworkInterfaces: [{ Attachment: {} }]
            });

            const result = await checkUnusedENIs("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("ENI found without ID");
        });
    });

    describe("Edge Cases", () => {
        it("should return NOTAPPLICABLE when no ENIs exist", async () => {
            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({
                NetworkInterfaces: []
            });

            const result = await checkUnusedENIs("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No ENIs found in the region");
        });

        it("should return ERROR when API call fails", async () => {
            mockEC2Client.on(DescribeNetworkInterfacesCommand).rejects(
                new Error("API Error")
            );

            const result = await checkUnusedENIs("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Error checking ENIs: API Error");
        });

        it("should handle undefined NetworkInterfaces in response", async () => {
            mockEC2Client.on(DescribeNetworkInterfacesCommand).resolves({});

            const result = await checkUnusedENIs("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
        });
    });
});