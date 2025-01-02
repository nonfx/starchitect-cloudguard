// @ts-nocheck
import {
	ECSClient,
	ListTaskDefinitionsCommand,
	DescribeTaskDefinitionCommand
} from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsContainerPrivileges from "./check-ecs-container-privileges";

const mockEcsClient = mockClient(ECSClient);

const mockTaskDefinitionArn1 = "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:1";
const mockTaskDefinitionArn2 = "arn:aws:ecs:us-east-1:123456789012:task-definition/test-task:2";

describe("checkEcsContainerPrivileges", () => {
	beforeEach(() => {
		mockEcsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when no containers are privileged", async () => {
			mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
				taskDefinitionArns: [mockTaskDefinitionArn1]
			});

			mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({
				taskDefinition: {
					containerDefinitions: [{ name: "container1", privileged: false }, { name: "container2" }]
				}
			});

			const result = await checkEcsContainerPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockTaskDefinitionArn1);
		});

		it("should return NOTAPPLICABLE when no task definitions exist", async () => {
			mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
				taskDefinitionArns: []
			});

			const result = await checkEcsContainerPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ECS task definitions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when containers are privileged", async () => {
			mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
				taskDefinitionArns: [mockTaskDefinitionArn1]
			});

			mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({
				taskDefinition: {
					containerDefinitions: [
						{ name: "container1", privileged: true },
						{ name: "container2", privileged: true }
					]
				}
			});

			const result = await checkEcsContainerPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("container1");
			expect(result.checks[0].message).toContain("container2");
		});

		it("should handle mixed privileged and non-privileged containers", async () => {
			mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
				taskDefinitionArns: [mockTaskDefinitionArn1, mockTaskDefinitionArn2]
			});

			mockEcsClient
				.on(DescribeTaskDefinitionCommand)
				.resolvesOnce({
					taskDefinition: {
						containerDefinitions: [{ name: "container1", privileged: true }]
					}
				})
				.resolvesOnce({
					taskDefinition: {
						containerDefinitions: [{ name: "container2", privileged: false }]
					}
				});

			const result = await checkEcsContainerPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListTaskDefinitions fails", async () => {
			mockEcsClient.on(ListTaskDefinitionsCommand).rejects(new Error("API Error"));

			const result = await checkEcsContainerPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ECS task definitions");
		});

		it("should handle task definitions without container definitions", async () => {
			mockEcsClient.on(ListTaskDefinitionsCommand).resolves({
				taskDefinitionArns: [mockTaskDefinitionArn1]
			});

			mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({
				taskDefinition: {}
			});

			const result = await checkEcsContainerPrivileges.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Task definition has no container definitions");
		});

		it("should handle pagination", async () => {
			mockEcsClient
				.on(ListTaskDefinitionsCommand)
				.resolvesOnce({
					taskDefinitionArns: [mockTaskDefinitionArn1],
					nextToken: "token1"
				})
				.resolvesOnce({
					taskDefinitionArns: [mockTaskDefinitionArn2]
				});

			mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({
				taskDefinition: {
					containerDefinitions: [{ name: "container1", privileged: false }]
				}
			});

			const result = await checkEcsContainerPrivileges.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});
});
