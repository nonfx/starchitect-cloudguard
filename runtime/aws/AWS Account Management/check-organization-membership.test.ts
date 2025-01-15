// @ts-nocheck
import { OrganizationsClient, DescribeOrganizationCommand } from "@aws-sdk/client-organizations";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkOrganizationMembership from "./check-organization-membership";

const mockOrganizationsClient = mockClient(OrganizationsClient);

const mockOrganization = {
    Id: "o-exampleorgid",
    Arn: "arn:aws:organizations::123456789012:organization/o-exampleorgid",
    FeatureSet: "ALL",
    MasterAccountArn: "arn:aws:organizations::123456789012:account/o-exampleorgid/123456789012",
    MasterAccountId: "123456789012",
    MasterAccountEmail: "main@example.com"
};

describe("checkOrganizationMembership", () => {
    beforeEach(() => {
        mockOrganizationsClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when account is part of an organization", async () => {
            mockOrganizationsClient.on(DescribeOrganizationCommand).resolves({
                Organization: mockOrganization
            });

            const result = await checkOrganizationMembership.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("AWS Account");
            expect(result.checks[0].resourceArn).toBe(mockOrganization.Arn);
            expect(result.checks[0].message).toContain(mockOrganization.Id);
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when account is not part of an organization", async () => {
            mockOrganizationsClient.on(DescribeOrganizationCommand).rejects({
                name: "AWSOrganizationsNotInUseException",
                message: "AWS Organizations is not in use"
            });

            const result = await checkOrganizationMembership.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Account is not part of an AWS Organization");
        });

        it("should return FAIL when organization details are empty", async () => {
            mockOrganizationsClient.on(DescribeOrganizationCommand).resolves({
                Organization: null
            });

            const result = await checkOrganizationMembership.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Account is not part of an AWS Organization");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when API call fails with unexpected error", async () => {
            mockOrganizationsClient.on(DescribeOrganizationCommand).rejects(
                new Error("Internal Server Error")
            );

            const result = await checkOrganizationMembership.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking organization membership");
            expect(result.checks[0].message).toContain("Internal Server Error");
        });

        it("should return ERROR when API call fails with access denied", async () => {
            mockOrganizationsClient.on(DescribeOrganizationCommand).rejects({
                name: "AccessDeniedException",
                message: "User is not authorized"
            });

            const result = await checkOrganizationMembership.execute();
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking organization membership");
            expect(result.checks[0].message).toContain("User is not authorized");
        });
    });

    describe("Region Handling", () => {
        it("should use provided region", async () => {
            mockOrganizationsClient.on(DescribeOrganizationCommand).resolves({
                Organization: mockOrganization
            });

            await checkOrganizationMembership.execute("us-west-2");
            const calls = mockOrganizationsClient.calls();
            
            expect(calls).toHaveLength(1);
            expect(calls[0].args[0].input).toEqual({});
        });

        it("should use default region if none provided", async () => {
            mockOrganizationsClient.on(DescribeOrganizationCommand).resolves({
                Organization: mockOrganization
            });

            await checkOrganizationMembership.execute();
            const calls = mockOrganizationsClient.calls();
            
            expect(calls).toHaveLength(1);
            expect(calls[0].args[0].input).toEqual({});
        });
    });
});