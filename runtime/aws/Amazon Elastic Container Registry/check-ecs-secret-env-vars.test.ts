// @ts-nocheck
import { ECSClient, ListTaskDefinitionsCommand, DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsSecretEnvVars from "./check-ecs-secret-env-vars";

const mockEcsClient = mockClient(ECSClient);

const mockTaskDefinitionArn = "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1";

describe("checkEcsSecretEnvVars", () => {
    beforeEach(() => {
        mockEcsClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when no sensitive environment variables are found", async () => {
            mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
                taskDefinitionArns: [mockTaskDefinitionArn]
            });

            mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({
                taskDefinition: {
                    containerDefinitions: [{
                        environment: [
                            { name: "NORMAL_VAR", value: "safe-value" },
                            { name: "APP_SETTING", value: "configuration" }
                        ]
                    }]
                }
            });

            const result = await checkEcsSecretEnvVars.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe(mockTaskDefinitionArn);
        });

        it("should return NOTAPPLICABLE when no task definitions exist", async () => {
            mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
                taskDefinitionArns: []
            });

            const result = await checkEcsSecretEnvVars.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No ECS task definitions found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when AWS credentials are found in environment variables", async () => {
            mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
                taskDefinitionArns: [mockTaskDefinitionArn]
            });

            mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({
                taskDefinition: {
                    containerDefinitions: [{
                        environment: [
                            { name: "AWS_ACCESS_KEY_ID", value: "AKIAIOSFODNN7EXAMPLE" },
                            { name: "AWS_SECRET_ACCESS_KEY", value: "secret" }
                        ]
                    }]
                }
            });

            const result = await checkEcsSecretEnvVars.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("sensitive information");
        });

        it("should return FAIL when sensitive variable names are found", async () => {
            mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
                taskDefinitionArns: [mockTaskDefinitionArn]
            });

            mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({
                taskDefinition: {
                    containerDefinitions: [{
                        environment: [
                            { name: "DATABASE_PASSWORD", value: "db-password" },
                            { name: "API_SECRET", value: "api-key" }
                        ]
                    }]
                }
            });

            const result = await checkEcsSecretEnvVars.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListTaskDefinitions fails", async () => {
            mockEcsClient.on(ListTaskDefinitionsCommand).rejects(
                new Error("Failed to list task definitions")
            );

            const result = await checkEcsSecretEnvVars.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to list task definitions");
        });

        it("should return ERROR when DescribeTaskDefinition fails", async () => {
            mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
                taskDefinitionArns: [mockTaskDefinitionArn]
            });

            mockEcsClient.on(DescribeTaskDefinitionCommand).rejects(
                new Error("Access denied")
            );

            const result = await checkEcsSecretEnvVars.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking task definition");
        });

        it("should handle task definitions without container definitions", async () => {
            mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
                taskDefinitionArns: [mockTaskDefinitionArn]
            });

            mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({
                taskDefinition: {}
            });

            const result = await checkEcsSecretEnvVars.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Task definition has no container definitions");
        });
    });
});