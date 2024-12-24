import { ECSClient, ListTaskDefinitionsCommand, DescribeTaskDefinitionCommand } from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "@codegen/utils/stringUtils";
import checkEcsContainerReadonlyRoot from "./check-ecs-container-readonly-root";

const mockECSClient = mockClient(ECSClient);

const mockTaskDefinitionArn = "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1";

const mockCompliantTaskDefinition = {
    taskDefinition: {
        containerDefinitions: [
            {
                name: "compliant-container",
                readonlyRootFilesystem: true
            },
            {
                name: "another-compliant-container",
                readonlyRootFilesystem: true
            }
        ]
    }
};

const mockNonCompliantTaskDefinition = {
    taskDefinition: {
        containerDefinitions: [
            {
                name: "non-compliant-container",
                readonlyRootFilesystem: false
            },
            {
                name: "missing-property-container"
            }
        ]
    }
};

describe("checkEcsContainerReadonlyRoot", () => {
    beforeEach(() => {
        mockECSClient.reset();
    });

    describe("Compliant Resources", () => {
        it("should return PASS when all containers have readonly root filesystem enabled", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .resolves(mockCompliantTaskDefinition);

            const result = await checkEcsContainerReadonlyRoot("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
            expect(result.checks[0].resourceArn).toBe(mockTaskDefinitionArn);
        });

        it("should return NOTAPPLICABLE when no task definitions exist", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [] });

            const result = await checkEcsContainerReadonlyRoot("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
            expect(result.checks[0].message).toBe("No ECS task definitions found in the region");
        });
    });

    describe("Non-Compliant Resources", () => {
        it("should return FAIL when containers have readonly root filesystem disabled", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .resolves(mockNonCompliantTaskDefinition);

            const result = await checkEcsContainerReadonlyRoot("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
            expect(result.checks[0].message).toContain("non-compliant-container");
            expect(result.checks[0].message).toContain("missing-property-container");
        });

        it("should return FAIL when task definition has missing container definitions", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .resolves({ taskDefinition: {} });

            const result = await checkEcsContainerReadonlyRoot("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toBe("Task definition missing container definitions");
        });
    });

    describe("Error Handling", () => {
        it("should return ERROR when ListTaskDefinitions fails", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .rejects(new Error("Failed to list task definitions"));

            const result = await checkEcsContainerReadonlyRoot("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Failed to list task definitions");
        });

        it("should return ERROR when DescribeTaskDefinition fails", async () => {
            mockECSClient
                .on(ListTaskDefinitionsCommand)
                .resolves({ taskDefinitionArns: [mockTaskDefinitionArn] });
            mockECSClient
                .on(DescribeTaskDefinitionCommand)
                .rejects(new Error("Access denied"));

            const result = await checkEcsContainerReadonlyRoot("us-east-1");
            expect(result.checks).toHaveLength(1);
            expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
            expect(result.checks[0].message).toContain("Access denied");
        });
    });

    it("should handle multiple task definitions with mixed compliance", async () => {
        const taskArn1 = mockTaskDefinitionArn;
        const taskArn2 = `${mockTaskDefinitionArn}:2`;
        
        mockECSClient
            .on(ListTaskDefinitionsCommand)
            .resolves({ taskDefinitionArns: [taskArn1, taskArn2] });
        
        mockECSClient
            .on(DescribeTaskDefinitionCommand, { taskDefinition: taskArn1 })
            .resolves(mockCompliantTaskDefinition)
            .on(DescribeTaskDefinitionCommand, { taskDefinition: taskArn2 })
            .resolves(mockNonCompliantTaskDefinition);

        const result = await checkEcsContainerReadonlyRoot("us-east-1");
        expect(result.checks).toHaveLength(2);
        expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
        expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
    });
});