//@ts-nocheck
import {
	ECSClient,
	DescribeTaskDefinitionCommand,
	ListTaskDefinitionsCommand
} from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsTaskDefinitionPidMode from "./check-ecs-task-definition-pid-mode";

const mockECSClient = mockClient(ECSClient);

const mockTaskDefinitionArn1 = "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1";
const mockTaskDefinitionArn2 = "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:2";

describe("checkEcsTaskDefinitionPidMode", () => {
	beforeEach(() => {
		mockECSClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when task definition has no pidMode set", async () => {
			mockECSClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArn1] });
			mockECSClient
				.on(DescribeTaskDefinitionCommand)
				.resolves({ taskDefinition: { taskDefinitionArn: mockTaskDefinitionArn1 } });

			const result = await checkEcsTaskDefinitionPidMode.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockTaskDefinitionArn1);
		});

		it("should return PASS when task definition has pidMode not set to host", async () => {
			mockECSClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArn1] });
			mockECSClient.on(DescribeTaskDefinitionCommand).resolves({
				taskDefinition: { taskDefinitionArn: mockTaskDefinitionArn1, pidMode: "task" }
			});

			const result = await checkEcsTaskDefinitionPidMode.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no task definitions exist", async () => {
			mockECSClient.on(ListTaskDefinitionsCommand).resolves({ taskDefinitionArns: [] });

			const result = await checkEcsTaskDefinitionPidMode.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ECS task definitions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when task definition has pidMode set to host", async () => {
			mockECSClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArn1] });
			mockECSClient.on(DescribeTaskDefinitionCommand).resolves({
				taskDefinition: { taskDefinitionArn: mockTaskDefinitionArn1, pidMode: "host" }
			});

			const result = await checkEcsTaskDefinitionPidMode.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Task definition shares host process namespace (pidMode: host)"
			);
		});

		it("should handle mixed compliant and non-compliant task definitions", async () => {
			mockECSClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArn1, mockTaskDefinitionArn2] });
			mockECSClient
				.on(DescribeTaskDefinitionCommand)
				.resolves({
					taskDefinition: { taskDefinitionArn: mockTaskDefinitionArn1, pidMode: "host" }
				})
				.on(DescribeTaskDefinitionCommand, { taskDefinition: mockTaskDefinitionArn2 })
				.resolves({ taskDefinition: { taskDefinitionArn: mockTaskDefinitionArn2 } });

			const result = await checkEcsTaskDefinitionPidMode.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListTaskDefinitions fails", async () => {
			mockECSClient
				.on(ListTaskDefinitionsCommand)
				.rejects(new Error("Failed to list task definitions"));

			const result = await checkEcsTaskDefinitionPidMode.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to list task definitions");
		});

		it("should return ERROR when DescribeTaskDefinition fails", async () => {
			mockECSClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArn1] });
			mockECSClient
				.on(DescribeTaskDefinitionCommand)
				.rejects(new Error("Failed to describe task definition"));

			const result = await checkEcsTaskDefinitionPidMode.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to describe task definition");
		});

		it("should return ERROR when task definition details are missing", async () => {
			mockECSClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArn1] });
			mockECSClient.on(DescribeTaskDefinitionCommand).resolves({});

			const result = await checkEcsTaskDefinitionPidMode.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to retrieve task definition details");
		});
	});
});
