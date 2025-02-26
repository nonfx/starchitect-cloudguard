//@ts-nocheck
import { CloudFormationClient, DescribeStacksCommand } from "@aws-sdk/client-cloudformation";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFormationStackNotifications from "./check-cloudformation-stack-notifications";

const mockCloudFormationClient = mockClient(CloudFormationClient);

const mockStackWithNotifications = {
	StackName: "test-stack-1",
	StackId: "arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack-1",
	NotificationARNs: ["arn:aws:sns:us-east-1:123456789012:test-topic"]
};

const mockStackWithoutNotifications = {
	StackName: "test-stack-2",
	StackId: "arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack-2",
	NotificationARNs: []
};

describe("checkCloudFormationStackNotifications", () => {
	beforeEach(() => {
		mockCloudFormationClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when stack has SNS notifications configured", async () => {
			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [mockStackWithNotifications]
			});

			const result = await checkCloudFormationStackNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-stack-1");
			expect(result.checks[0].resourceArn).toBe(mockStackWithNotifications.StackId);
		});

		it("should handle multiple compliant stacks", async () => {
			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [
					mockStackWithNotifications,
					{ ...mockStackWithNotifications, StackName: "test-stack-3" }
				]
			});

			const result = await checkCloudFormationStackNotifications.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when stack has no SNS notifications", async () => {
			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [mockStackWithoutNotifications]
			});

			const result = await checkCloudFormationStackNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudFormation stack does not have SNS notifications configured"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [mockStackWithNotifications, mockStackWithoutNotifications]
			});

			const result = await checkCloudFormationStackNotifications.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		it("should return NOTAPPLICABLE when no stacks exist", async () => {
			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: []
			});

			const result = await checkCloudFormationStackNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFormation stacks found in the region");
		});

		it("should handle stack without name", async () => {
			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [{ NotificationARNs: [] }]
			});

			const result = await checkCloudFormationStackNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Stack found without name");
		});

		it("should handle API errors", async () => {
			mockCloudFormationClient.on(DescribeStacksCommand).rejects(new Error("API Error"));

			const result = await checkCloudFormationStackNotifications.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudFormation stacks");
		});

		it("should handle pagination", async () => {
			mockCloudFormationClient
				.on(DescribeStacksCommand)
				.resolvesOnce({
					Stacks: [mockStackWithNotifications],
					NextToken: "token1"
				})
				.resolvesOnce({
					Stacks: [mockStackWithoutNotifications]
				});

			const result = await checkCloudFormationStackNotifications.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
