// @ts-nocheck
import {
	ECSClient,
	ListTaskDefinitionsCommand,
	DescribeTaskDefinitionCommand
} from "@aws-sdk/client-ecs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEcsTaskSecurity from "./check-ecs-task-security";

const mockEcsClient = mockClient(ECSClient);

const mockTaskDefinitionArns = [
	"arn:aws:ecs:us-east-1:123456789012:task-definition/secure-task:1",
	"arn:aws:ecs:us-east-1:123456789012:task-definition/insecure-task:1"
];

const mockSecureTaskDefinition = {
	taskDefinition: {
		networkMode: "host",
		containerDefinitions: [
			{
				user: "1000:1000",
				privileged: false
			}
		]
	}
};

const mockInsecureTaskDefinition = {
	taskDefinition: {
		networkMode: "host",
		containerDefinitions: [
			{
				user: "root",
				privileged: true
			}
		]
	}
};

const mockBridgeNetworkTaskDefinition = {
	taskDefinition: {
		networkMode: "bridge",
		containerDefinitions: [
			{
				user: "root",
				privileged: true
			}
		]
	}
};

describe("checkEcsTaskSecurity", () => {
	beforeEach(() => {
		mockEcsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for task definitions with secure configuration in host network mode", async () => {
			mockEcsClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArns[0]] });
			mockEcsClient.on(DescribeTaskDefinitionCommand).resolves(mockSecureTaskDefinition);

			const result = await checkEcsTaskSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(mockTaskDefinitionArns[0]);
		});

		it("should return PASS for task definitions not using host network mode", async () => {
			mockEcsClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArns[0]] });
			mockEcsClient.on(DescribeTaskDefinitionCommand).resolves(mockBridgeNetworkTaskDefinition);

			const result = await checkEcsTaskSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no task definitions exist", async () => {
			mockEcsClient.on(ListTaskDefinitionsCommand).resolves({ taskDefinitionArns: [] });

			const result = await checkEcsTaskSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No ECS task definitions found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for task definitions with insecure configuration in host network mode", async () => {
			mockEcsClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArns[1]] });
			mockEcsClient.on(DescribeTaskDefinitionCommand).resolves(mockInsecureTaskDefinition);

			const result = await checkEcsTaskSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("must use non-root users");
		});

		it("should handle multiple task definitions with mixed compliance", async () => {
			mockEcsClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: mockTaskDefinitionArns });
			mockEcsClient
				.on(DescribeTaskDefinitionCommand)
				.resolvesOnce(mockSecureTaskDefinition)
				.resolvesOnce(mockInsecureTaskDefinition);

			const result = await checkEcsTaskSecurity.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListTaskDefinitions fails", async () => {
			mockEcsClient.on(ListTaskDefinitionsCommand).rejects(new Error("API Error"));

			const result = await checkEcsTaskSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking ECS task definitions");
		});

		it("should return ERROR when DescribeTaskDefinition fails", async () => {
			mockEcsClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArns[0]] });
			mockEcsClient.on(DescribeTaskDefinitionCommand).rejects(new Error("Access Denied"));

			const result = await checkEcsTaskSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking task definition");
		});

		it("should handle missing taskDefinition in response", async () => {
			mockEcsClient
				.on(ListTaskDefinitionsCommand)
				.resolves({ taskDefinitionArns: [mockTaskDefinitionArns[0]] });
			mockEcsClient.on(DescribeTaskDefinitionCommand).resolves({});

			const result = await checkEcsTaskSecurity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Unable to retrieve task definition details");
		});
	});
});
