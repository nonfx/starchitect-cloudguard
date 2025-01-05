// @ts-nocheck
import { IAMClient, ListPoliciesCommand, GetPolicyVersionCommand } from "@aws-sdk/client-iam";
import { LightsailClient, GetBucketsCommand } from "@aws-sdk/client-lightsail";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkLightsailBucketAccess from "./check-lightsail-bucket-access";

const mockIAMClient = mockClient(IAMClient);
const mockLightsailClient = mockClient(LightsailClient);

const validPolicyDocument = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["lightsail:*"],
			Resource: "*"
		},
		{
			Effect: "Allow",
			Action: ["s3:*"],
			Resource: ["arn:aws:s3:::bucket1/*", "arn:aws:s3:::bucket2/*"]
		}
	]
};

const partialPolicyDocument = {
	Version: "2012-10-17",
	Statement: [
		{
			Effect: "Allow",
			Action: ["lightsail:*"],
			Resource: "*"
		},
		{
			Effect: "Allow",
			Action: ["s3:*"],
			Resource: "arn:aws:s3:::bucket1/*"
		}
	]
};

const invalidPolicyDocument = {
	Version: "2012-10-17",
	Statement: {
		Effect: "Allow",
		Action: "*",
		Resource: "*"
	}
};

describe("checkLightsailBucketAccess", () => {
	beforeEach(() => {
		mockIAMClient.reset();
		mockLightsailClient.reset();

		// Default Lightsail buckets response
		mockLightsailClient.on(GetBucketsCommand).resolves({
			buckets: [{ name: "bucket1" }, { name: "bucket2" }]
		});
	});

	describe("Compliant Resources", () => {
		it("should return PASS for buckets with valid access in any policy", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "Policy1",
						Arn: "arn:aws:iam::123456789012:policy/Policy1",
						DefaultVersionId: "v1"
					},
					{
						PolicyName: "Policy2",
						Arn: "arn:aws:iam::123456789012:policy/Policy2",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient
				.on(GetPolicyVersionCommand)
				.resolvesOnce({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(partialPolicyDocument))
					}
				})
				.resolvesOnce({
					PolicyVersion: {
						Document: encodeURIComponent(JSON.stringify(validPolicyDocument))
					}
				});

			const result = await checkLightsailBucketAccess.execute();

			// Both buckets should pass because they're covered by at least one policy
			expect(result.checks.filter(check => check.status === ComplianceStatus.PASS)).toHaveLength(2);
			expect(result.checks.filter(check => check.status === ComplianceStatus.FAIL)).toHaveLength(0);
		});

		it("should return NOTAPPLICABLE when no Lightsail buckets exist", async () => {
			mockLightsailClient.on(GetBucketsCommand).resolves({
				buckets: []
			});

			const result = await checkLightsailBucketAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No Lightsail buckets found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL only for buckets without proper access in any policy", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "PartialPolicy",
						Arn: "arn:aws:iam::123456789012:policy/PartialPolicy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(partialPolicyDocument))
				}
			});

			const result = await checkLightsailBucketAccess.execute();

			const passingChecks = result.checks.filter(check => check.status === ComplianceStatus.PASS);
			const failingChecks = result.checks.filter(check => check.status === ComplianceStatus.FAIL);

			expect(passingChecks).toHaveLength(1);
			expect(failingChecks).toHaveLength(1);
			expect(passingChecks[0].resourceName).toBe("bucket1");
			expect(failingChecks[0].resourceName).toBe("bucket2");
		});

		it("should return FAIL for all buckets when no valid policies exist", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "InvalidPolicy",
						Arn: "arn:aws:iam::123456789012:policy/InvalidPolicy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent(JSON.stringify(invalidPolicyDocument))
				}
			});

			const result = await checkLightsailBucketAccess.execute();
			const failingChecks = result.checks.filter(check => check.status === ComplianceStatus.FAIL);
			expect(failingChecks).toHaveLength(2);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when Lightsail bucket fetch fails", async () => {
			mockLightsailClient.on(GetBucketsCommand).rejects(new Error("Lightsail API Error"));

			const result = await checkLightsailBucketAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Failed to fetch Lightsail buckets");
		});

		it("should return ERROR when ListPolicies fails", async () => {
			mockIAMClient.on(ListPoliciesCommand).rejects(new Error("IAM API Error"));

			const result = await checkLightsailBucketAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking IAM policies");
		});

		it("should handle missing policy version document", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "MissingVersionPolicy",
						Arn: "arn:aws:iam::123456789012:policy/MissingVersionPolicy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: { Document: null }
			});

			const result = await checkLightsailBucketAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Policy version document is empty");
		});

		it("should handle invalid JSON in policy document", async () => {
			mockIAMClient.on(ListPoliciesCommand).resolves({
				Policies: [
					{
						PolicyName: "InvalidJsonPolicy",
						Arn: "arn:aws:iam::123456789012:policy/InvalidJsonPolicy",
						DefaultVersionId: "v1"
					}
				]
			});

			mockIAMClient.on(GetPolicyVersionCommand).resolves({
				PolicyVersion: {
					Document: encodeURIComponent("invalid-json")
				}
			});

			const result = await checkLightsailBucketAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error analyzing policy");
		});
	});
});
