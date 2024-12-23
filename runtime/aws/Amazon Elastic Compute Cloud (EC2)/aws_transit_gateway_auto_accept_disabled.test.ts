import { EC2Client, DescribeTransitGatewaysCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkTransitGatewayAutoAccept from "./aws_transit_gateway_auto_accept_disabled";

const mockEC2Client = mockClient(EC2Client);

const mockTransitGatewayCompliant = {
    TransitGatewayId: "tgw-123456789",
    TransitGatewayArn: "arn:aws:ec2:us-east-1:123456789012:transit-gateway/tgw-123456789",
    Options: {
        AutoAcceptSharedAttachments: "disable"
    }
};

const mockTransitGatewayNonCompliant = {
    TransitGatewayId: "tgw-987654321",
    TransitGatewayArn: "arn:aws:ec2:us-east-1:123456789012:transit-gateway/tgw-987654321",
    Options: {
        AutoAcceptSharedAttachments: "enable"
    }
};

describe("checkTransitGatewayAutoAccept", () => {
    beforeEach(() => {
        mockEC2Client.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when auto-accept is disabled", async () => {
            mockEC2Client.on(DescribeTransitGatewaysCommand).resolves({
                TransitGateways: [mockTransitGatewayCompliant]
            });

            const result = await checkTransitGatewayAutoAccept("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("tgw-123456789");
            expect(result.checks[0].resourceArn).toBe(mockTransitGatewayCompliant.TransitGatewayArn);
        });

        it("should return NOTAPPLICABLE when no transit gateways exist", async () => {
            mockEC2Client.on(DescribeTransitGatewaysCommand).resolves({
                TransitGateways: []
            });

            const result = await checkTransitGatewayAutoAccept("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No Transit Gateways found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when auto-accept is enabled", async () => {
            mockEC2Client.on(DescribeTransitGatewaysCommand).resolves({
                TransitGateways: [mockTransitGatewayNonCompliant]
            });

            const result = await checkTransitGatewayAutoAccept("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe(
                "Transit Gateway is configured to automatically accept VPC attachment requests"
            );
        });

        it("should handle multiple transit gateways with mixed compliance", async () => {
            mockEC2Client.on(DescribeTransitGatewaysCommand).resolves({
                TransitGateways: [mockTransitGatewayCompliant, mockTransitGatewayNonCompliant]
            });

            const result = await checkTransitGatewayAutoAccept("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });

        it("should return ERROR for transit gateway without ID or ARN", async () => {
            mockEC2Client.on(DescribeTransitGatewaysCommand).resolves({
                TransitGateways: [{ Options: { AutoAcceptSharedAttachments: "enable" } }]
            });

            const result = await checkTransitGatewayAutoAccept("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Transit Gateway found without ID or ARN");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails", async () => {
            mockEC2Client.on(DescribeTransitGatewaysCommand).rejects(
                new Error("API call failed")
            );

            const result = await checkTransitGatewayAutoAccept("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking Transit Gateways");
        });
    });
});