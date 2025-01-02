// @ts-nocheck
import { ECSClient, ListTaskDefinitionsCommand, DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsTaskDefinitionLogging from "./check-ecs-task-definition-logging";

const mockECSClient = mockClient(ECSClient);

const mockTaskDefinitionArn = "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1";

const mockTaskDefinitionWithLogging = {
    taskDefinition: {
        containerDefinitions: [
            {
                name: "container1",
                logConfiguration: {
                    logDriver: "awslogs"
                }
            },
            {
                name: "container2",
                logConfiguration: {
                    logDriver: "awslogs"
                }
            }
        ]
    }
};

const mockTaskDefinitionWithoutLogging = {
    taskDefinition: {
        containerDefinitions: [
            {
                name: "container1",
                logConfiguration: {
                    logDriver: "awslogs"
                }
            },
            {
                name: "container2"
            }
        ]
    }
};

describe("checkEcsTaskDefinitionLogging", () => {
    beforeEach(() => {
        mockECSClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when all containers have logging configured", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .resolves(mockTaskDefinitionWithLogging);

            const result = await checkEcsTaskDefinitionLogging.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceName).toBe(mockTaskDefinitionArn);
        });

        it("should return NOTAPPLICABLE when no task definitions exist", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [] });

            const result = await checkEcsTaskDefinitionLogging.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No ECS task definitions found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when some containers lack logging configuration", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .resolves(mockTaskDefinitionWithoutLogging);

            const result = await checkEcsTaskDefinitionLogging.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toBe(
                "One or more containers in the task definition do not have logging configuration"
            );
        });

        it("should handle multiple task definitions with mixed compliance", async () => {
            const secondTaskDefArn = `${mockTaskDefinitionArn}:2`;
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn, secondTaskDefArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .resolves(mockTaskDefinitionWithLogging)
                .on(DescribeTaskDefinitionCommand, { taskDefinition: secondTaskDefArn })
                .resolves(mockTaskDefinitionWithoutLogging);

            const result = await checkEcsTaskDefinitionLogging.execute("us-east-1");
            expect(result.checks).toHaveLength(2);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListTaskDefinitions fails", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .rejects(new Error("Failed to list task definitions"));

            const result = await checkEcsTaskDefinitionLogging.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error listing task definitions");
        });

        it("should return ERROR when DescribeTaskDefinition fails", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .rejects(new Error("Access denied"));

            const result = await checkEcsTaskDefinitionLogging.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Error checking task definition");
        });

        it("should handle missing taskDefinition in response", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .resolves({});

            const result = await checkEcsTaskDefinitionLogging.execute("us-east-1");
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Unable to retrieve task definition details");
        });
    });
});