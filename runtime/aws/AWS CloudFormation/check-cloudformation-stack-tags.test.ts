// @ts-nocheck
import {
	CloudFormationClient,
	ListStacksCommand,
	DescribeStacksCommand
} from "@aws-sdk/client-cloudformation";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkCloudFormationStackTags from "./check-cloudformation-stack-tags";

const mockCloudFormationClient = mockClient(CloudFormationClient);

const mockStackSummaries = [
	{
		StackName: "test-stack-1",
		StackId: "arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack-1/abc123"
	},
	{
		StackName: "test-stack-2",
		StackId: "arn:aws:cloudformation:us-east-1:123456789012:stack/test-stack-2/def456"
	}
];

describe("checkCloudFormationStackTags", () => {
	beforeEach(() => {
		mockCloudFormationClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when stacks have user-defined tags", async () => {
			mockCloudFormationClient.on(ListStacksCommand).resolves({
				StackSummaries: mockStackSummaries
			});

			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [
					{
						StackName: "test-stack-1",
						StackId: mockStackSummaries[0].StackId,
						Tags: [
							{ Key: "Environment", Value: "Production" },
							{ Key: "aws:cloudformation:stack-name", Value: "test-stack-1" }
						]
					}
				]
			});

			const result = await checkCloudFormationStackTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-stack-1");
			expect(result.checks[0].resourceArn).toBe(mockStackSummaries[0].StackId);
		});

		it("should ignore system tags starting with aws:", async () => {
			mockCloudFormationClient.on(ListStacksCommand).resolves({
				StackSummaries: [mockStackSummaries[0]]
			});

			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [
					{
						StackName: "test-stack-1",
						StackId: mockStackSummaries[0].StackId,
						Tags: [
							{ Key: "aws:cloudformation:stack-name", Value: "test-stack-1" },
							{ Key: "Environment", Value: "Production" }
						]
					}
				]
			});

			const result = await checkCloudFormationStackTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when stacks have no user-defined tags", async () => {
			mockCloudFormationClient.on(ListStacksCommand).resolves({
				StackSummaries: [mockStackSummaries[0]]
			});

			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [
					{
						StackName: "test-stack-1",
						StackId: mockStackSummaries[0].StackId,
						Tags: [{ Key: "aws:cloudformation:stack-name", Value: "test-stack-1" }]
					}
				]
			});

			const result = await checkCloudFormationStackTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"CloudFormation stack does not have any user-defined tags"
			);
		});

		it("should return FAIL when stacks have no tags at all", async () => {
			mockCloudFormationClient.on(ListStacksCommand).resolves({
				StackSummaries: [mockStackSummaries[0]]
			});

			mockCloudFormationClient.on(DescribeStacksCommand).resolves({
				Stacks: [
					{
						StackName: "test-stack-1",
						StackId: mockStackSummaries[0].StackId,
						Tags: []
					}
				]
			});

			const result = await checkCloudFormationStackTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no stacks exist", async () => {
			mockCloudFormationClient.on(ListStacksCommand).resolves({
				StackSummaries: []
			});

			const result = await checkCloudFormationStackTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No CloudFormation stacks found in the region");
		});

		it("should return ERROR when ListStacks fails", async () => {
			mockCloudFormationClient.on(ListStacksCommand).rejects(new Error("API Error"));

			const result = await checkCloudFormationStackTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking CloudFormation stacks");
		});

		it("should return ERROR for specific stack when DescribeStacks fails", async () => {
			mockCloudFormationClient.on(ListStacksCommand).resolves({
				StackSummaries: [mockStackSummaries[0]]
			});

			mockCloudFormationClient.on(DescribeStacksCommand).rejects(new Error("Access Denied"));

			const result = await checkCloudFormationStackTags.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking stack tags");
		});
	});
});
