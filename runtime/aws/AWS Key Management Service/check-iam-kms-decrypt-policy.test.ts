import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkIamKmsDecryptPolicy from "./check-iam-kms-decrypt-policy";

const mockIAMClient = mockClient(IAMClient);

const mockPolicy = {
    PolicyName: "test-policy",
    Arn: "arn:aws:iam::123456789012:policy/test-policy",
    DefaultVersionId: "v1"
};

describe("checkIamKmsDecryptPolicy", () => {
    beforeEach(() => {
        mockIAMClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS for policy with restricted KMS decrypt actions", async () => {
            const compliantPolicyDocument = {
                Version: "2012-10-17",
                Statement: [{
                    Effect: "Allow",
                    Action: ["kms:Decrypt"],
                    Resource: ["arn:aws:kms:us-east-1:123456789012:key/specific-key-id"]
                }]
            };

            mockIAMClient
                .on(ListPoliciesCommand)
                .resolves({ Policies: [mockPolicy] })
                .on(GetPolicyVersionCommand)
                .resolves({ 
                    PolicyVersion: { 
                        Document: encodeURIComponent(JSON.stringify(compliantPolicyDocument))
                    }
                });

            const result = await checkIamKmsDecryptPolicy();
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe("test-policy");
        });

        it("should return NOTAPPLICABLE when no policies exist", async () => {
            mockIAMClient
                .on(ListPoliciesCommand)
                .resolves({ Policies: [] });

            const result = await checkIamKmsDecryptPolicy();
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No customer managed policies found");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL for policy with unrestricted KMS decrypt actions", async () => {
            const nonCompliantPolicyDocument = {
                Version: "2012-10-17",
                Statement: [{
                    Effect: "Allow",
                    Action: ["kms:Decrypt"],
                    Resource: ["*"]
                }]
            };

            mockIAMClient
                .on(ListPoliciesCommand)
                .resolves({ Policies: [mockPolicy] })
                .on(GetPolicyVersionCommand)
                .resolves({ 
                    PolicyVersion: { 
                        Document: encodeURIComponent(JSON.stringify(nonCompliantPolicyDocument))
                    }
                });

            const result = await checkIamKmsDecryptPolicy();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe("Policy allows KMS decryption actions on all keys");
        });

        it("should return FAIL for policy with wildcard KMS actions", async () => {
            const wildcardPolicyDocument = {
                Version: "2012-10-17",
                Statement: [{
                    Effect: "Allow",
                    Action: ["kms:*"],
                    Resource: ["*"]
                }]
            };

            mockIAMClient
                .on(ListPoliciesCommand)
                .resolves({ Policies: [mockPolicy] })
                .on(GetPolicyVersionCommand)
                .resolves({ 
                    PolicyVersion: { 
                        Document: encodeURIComponent(JSON.stringify(wildcardPolicyDocument))
                    }
                });

            const result = await checkIamKmsDecryptPolicy();
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListPolicies fails", async () => {
            mockIAMClient
                .on(ListPoliciesCommand)
                .rejects(new Error("API Error"));

            const result = await checkIamKmsDecryptPolicy();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error listing policies");
        });

        it("should return ERROR when GetPolicyVersion fails", async () => {
            mockIAMClient
                .on(ListPoliciesCommand)
                .resolves({ Policies: [mockPolicy] })
                .on(GetPolicyVersionCommand)
                .rejects(new Error("Version fetch error"));

            const result = await checkIamKmsDecryptPolicy();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error fetching policy version");
        });

        it("should handle invalid policy documents", async () => {
            mockIAMClient
                .on(ListPoliciesCommand)
                .resolves({ Policies: [mockPolicy] })
                .on(GetPolicyVersionCommand)
                .resolves({ 
                    PolicyVersion: { 
                        Document: "invalid-json"
                    }
                });

            const result = await checkIamKmsDecryptPolicy();
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error parsing policy document");
        });
    });

    it("should handle pagination", async () => {
        const policy1 = { ...mockPolicy, PolicyName: "policy-1" };
        const policy2 = { ...mockPolicy, PolicyName: "policy-2" };

        mockIAMClient
            .on(ListPoliciesCommand)
            .resolvesOnce({ 
                Policies: [policy1],
                Marker: "next-token"
            })
            .resolvesOnce({ 
                Policies: [policy2]
            });

        mockIAMClient
            .on(GetPolicyVersionCommand)
            .resolves({ 
                PolicyVersion: { 
                    Document: encodeURIComponent(JSON.stringify({
                        Version: "2012-10-17",
                        Statement: [{
                            Effect: "Allow",
                            Action: ["kms:Decrypt"],
                            Resource: ["*"]
                        }]
                    }))
                }
            });

        const result = await checkIamKmsDecryptPolicy();
        expect(result.checks).toHaveLength(2);
    });
});