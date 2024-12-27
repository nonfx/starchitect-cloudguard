// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import checkIamFullAdminPrivileges from "./aws_iam_no_full_admin";

const mockIAMClient = mockClient(IAMClient);

describe("checkIamFullAdminPrivileges", () => {
	beforeEach(() => {
		mockIAMClient.reset();
	});

	it("should return FAIL when policy has full admin (*) privileges", async () => {
		mockIAMClient
			.on(ListPoliciesCommand)
			.resolves({
				Policies: [
					{
						PolicyName: "AdminPolicy",
						Arn: "arn:aws:iam::123456789012:policy/AdminPolicy",
						DefaultVersionId: "v1"
					}
				]
			})
			.on(GetPolicyVersionCommand)
			.resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: "*",
									Resource: "*"
								}
							]
						})
					)
				}
			});

		const result = await checkIamFullAdminPrivileges.execute();
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[0].message).toContain("full administrative privileges");
	});

	it("should return FAIL when policy has *:* action", async () => {
		mockIAMClient
			.on(ListPoliciesCommand)
			.resolves({
				Policies: [
					{
						PolicyName: "StarColonStar",
						Arn: "arn:aws:iam::123456789012:policy/StarColonStar",
						DefaultVersionId: "v1"
					}
				]
			})
			.on(GetPolicyVersionCommand)
			.resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: "*:*",
									Resource: "*"
								}
							]
						})
					)
				}
			});

		const result = await checkIamFullAdminPrivileges.execute();
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
	});

	it("should return PASS when policy has limited scope", async () => {
		mockIAMClient
			.on(ListPoliciesCommand)
			.resolves({
				Policies: [
					{
						PolicyName: "LimitedPolicy",
						Arn: "arn:aws:iam::123456789012:policy/LimitedPolicy",
						DefaultVersionId: "v1"
					}
				]
			})
			.on(GetPolicyVersionCommand)
			.resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: ["s3:GetObject", "s3:PutObject"],
									Resource: "arn:aws:s3:::specific-bucket/*"
								}
							]
						})
					)
				}
			});

		const result = await checkIamFullAdminPrivileges.execute();
		expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
	});

	it("should handle mixed policy types correctly", async () => {
		mockIAMClient.on(ListPoliciesCommand).resolves({
			Policies: [
				{
					PolicyName: "AdminPolicy",
					Arn: "arn:aws:iam::123456789012:policy/AdminPolicy",
					DefaultVersionId: "v1"
				},
				{
					PolicyName: "LimitedPolicy",
					Arn: "arn:aws:iam::123456789012:policy/LimitedPolicy",
					DefaultVersionId: "v1"
				}
			]
		});

		mockIAMClient
			.on(GetPolicyVersionCommand, {
				PolicyArn: "arn:aws:iam::123456789012:policy/AdminPolicy"
			})
			.resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: "*",
									Resource: "*"
								}
							]
						})
					)
				}
			});

		mockIAMClient
			.on(GetPolicyVersionCommand, {
				PolicyArn: "arn:aws:iam::123456789012:policy/LimitedPolicy"
			})
			.resolves({
				PolicyVersion: {
					Document: encodeURIComponent(
						JSON.stringify({
							Version: "2012-10-17",
							Statement: [
								{
									Effect: "Allow",
									Action: "s3:GetObject",
									Resource: "arn:aws:s3:::my-bucket/*"
								}
							]
						})
					)
				}
			});

		const result = await checkIamFullAdminPrivileges.execute();
		expect(result.checks).toHaveLength(2);
		expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
	});

	it("should return NOTAPPLICABLE when no policies exist", async () => {
		mockIAMClient.on(ListPoliciesCommand).resolves({ Policies: [] });

		const result = await checkIamFullAdminPrivileges.execute();
		expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
		expect(result.checks[0].message).toBe("No customer managed policies found");
	});

	it("should return ERROR on API failure", async () => {
		mockIAMClient.on(ListPoliciesCommand).rejects(new Error("API Error"));

		const result = await checkIamFullAdminPrivileges.execute();
		expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
		expect(result.checks[0].message).toContain("Error listing policies");
	});
});
