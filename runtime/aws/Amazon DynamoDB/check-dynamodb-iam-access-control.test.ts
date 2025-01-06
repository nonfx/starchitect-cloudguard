// @ts-nocheck
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkDynamoDBIAMAccessControl from "./check-dynamodb-iam-access-control";

const mockIAMClient = mockClient(IAMClient);

describe("checkDynamoDBIAMAccessControl", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when policy has DynamoDB actions with conditions", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "DynamoDBPolicy",
						Arn: "arn:aws:iam::123456789012:policy/DynamoDBPolicy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: JSON.stringify({
						Statement: [
							{
								Effect: "Allow",
								Action: ["dynamodb:GetItem"],
								Resource: "*",
								Condition: {
									"dynamodb:LeadingKeys": ["${aws:userid}"]
								}
							}
						]
					})
				}
			});

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("DynamoDBPolicy");
		});

		it("should return NOTAPPLICABLE when no DynamoDB policies exist", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "S3Policy",
						Arn: "arn:aws:iam::123456789012:policy/S3Policy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: JSON.stringify({
						Statement: [
							{
								Effect: "Allow",
								Action: ["s3:GetObject"],
								Resource: "*"
							}
						]
					})
				}
			});

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No IAM policies found with DynamoDB permissions");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when policy has DynamoDB actions without conditions", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "DynamoDBPolicy",
						Arn: "arn:aws:iam::123456789012:policy/DynamoDBPolicy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: JSON.stringify({
						Statement: [
							{
								Effect: "Allow",
								Action: ["dynamodb:GetItem"],
								Resource: "*"
							}
						]
					})
				}
			});

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].resourceName).toBe("DynamoDBPolicy");
		});

		it("should handle mixed policy scenarios", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "DynamoDBPolicyWithCondition",
						Arn: "arn:aws:iam::123456789012:policy/DynamoDBPolicyWithCondition",
						DefaultVersionId: "v1"
					},
					{
						PolicyName: "DynamoDBPolicyWithoutCondition",
						Arn: "arn:aws:iam::123456789012:policy/DynamoDBPolicyWithoutCondition",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient
				.on(GetPolicyVersionCommand, {
					PolicyArn: "arn:aws:iam::123456789012:policy/DynamoDBPolicyWithCondition",
					VersionId: "v1"
				})
				.resolves({
					PolicyVersion: {
						Document: JSON.stringify({
							Statement: [
								{
									Effect: "Allow",
									Action: ["dynamodb:GetItem"],
									Resource: "*",
									Condition: {
										"dynamodb:LeadingKeys": ["${aws:userid}"]
									}
								}
							]
						})
					}
				})
				.on(GetPolicyVersionCommand, {
					PolicyArn: "arn:aws:iam::123456789012:policy/DynamoDBPolicyWithoutCondition",
					VersionId: "v1"
				})
				.resolves({
					PolicyVersion: {
						Document: JSON.stringify({
							Statement: [
								{
									Effect: "Allow",
									Action: ["dynamodb:GetItem"],
									Resource: "*"
								}
							]
						})
					}
				});

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListPolicies fails", async () => {
			mockIAMClient.on(ListPoliciesCommand).rejects(new Error("Failed to list policies"));

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DynamoDB tables");
		});

		it("should return ERROR when GetPolicyVersion fails", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "DynamoDBPolicy",
						Arn: "arn:aws:iam::123456789012:policy/DynamoDBPolicy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).rejects(new Error("Failed to get policy version"));

			const result = await checkDynamoDBIAMAccessControl.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking DynamoDB tables");
		});
	});
});
