// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	S3Control,
	ListAccessPointsCommand,
	GetAccessPointCommand
} from "@aws-sdk/client-s3-control";
import { STSClient, GetCallerIdentityCommand } from "@aws-sdk/client-sts";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkS3AccessPointBlockPublicAccess from "./check-s3-access-point-block-public-access";

const mockS3ControlClient = mockClient(S3Control);
const mockSTSClient = mockClient(STSClient);

const mockAccountId = "123456789012";
const mockAccessPoints = [
	{
		Name: "test-access-point-1",
		AccessPointArn: "arn:aws:s3:us-east-1:123456789012:accesspoint/test-access-point-1"
	},
	{
		Name: "test-access-point-2",
		AccessPointArn: "arn:aws:s3:us-east-1:123456789012:accesspoint/test-access-point-2"
	}
];

describe("checkS3AccessPointBlockPublicAccess", () => {
	beforeEach(() => {
		mockS3ControlClient.reset();
		mockSTSClient.reset();
		// Mock STS GetCallerIdentity for all tests
		mockSTSClient.on(GetCallerIdentityCommand).resolves({ Account: mockAccountId });
	});

	describe("Compliant Resources", () => {
		it("should return PASS when access point has all block public access settings enabled", async () => {
			mockS3ControlClient
				.on(ListAccessPointsCommand)
				.resolves({ AccessPointList: [mockAccessPoints[0]] })
				.on(GetAccessPointCommand)
				.resolves({
					PublicAccessBlockConfiguration: {
						BlockPublicAcls: true,
						BlockPublicPolicy: true,
						IgnorePublicAcls: true,
						RestrictPublicBuckets: true
					}
				});

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-access-point-1");
		});

		it("should handle multiple compliant access points", async () => {
			mockS3ControlClient
				.on(ListAccessPointsCommand)
				.resolves({ AccessPointList: mockAccessPoints })
				.on(GetAccessPointCommand)
				.resolves({
					PublicAccessBlockConfiguration: {
						BlockPublicAcls: true,
						BlockPublicPolicy: true,
						IgnorePublicAcls: true,
						RestrictPublicBuckets: true
					}
				});

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when access point has no public access block configuration", async () => {
			mockS3ControlClient
				.on(ListAccessPointsCommand)
				.resolves({ AccessPointList: [mockAccessPoints[0]] })
				.on(GetAccessPointCommand)
				.resolves({});

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No public access block configuration found for access point"
			);
		});

		it("should return FAIL when access point has incomplete block settings", async () => {
			mockS3ControlClient
				.on(ListAccessPointsCommand)
				.resolves({ AccessPointList: [mockAccessPoints[0]] })
				.on(GetAccessPointCommand)
				.resolves({
					PublicAccessBlockConfiguration: {
						BlockPublicAcls: true,
						BlockPublicPolicy: false,
						IgnorePublicAcls: true,
						RestrictPublicBuckets: true
					}
				});

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Access point does not have all public access block settings enabled"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockS3ControlClient
				.on(ListAccessPointsCommand)
				.resolves({ AccessPointList: mockAccessPoints })
				.on(GetAccessPointCommand)
				.callsFake(input => {
					return Promise.resolve({
						PublicAccessBlockConfiguration:
							input.Name === "test-access-point-1"
								? {
										BlockPublicAcls: true,
										BlockPublicPolicy: true,
										IgnorePublicAcls: true,
										RestrictPublicBuckets: true
									}
								: {
										BlockPublicAcls: true,
										BlockPublicPolicy: false,
										IgnorePublicAcls: true,
										RestrictPublicBuckets: true
									}
					});
				});

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return NOTAPPLICABLE when no access points exist", async () => {
			mockS3ControlClient.on(ListAccessPointsCommand).resolves({ AccessPointList: [] });

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 access points found in the account");
		});

		it("should return ERROR when ListAccessPoints fails", async () => {
			mockS3ControlClient.on(ListAccessPointsCommand).rejects(new Error("API Error"));

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking S3 access points");
		});

		it("should return ERROR when GetAccessPoint fails", async () => {
			mockS3ControlClient
				.on(ListAccessPointsCommand)
				.resolves({ AccessPointList: [mockAccessPoints[0]] })
				.on(GetAccessPointCommand)
				.rejects(new Error("Access Denied"));

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking access point");
		});

		it("should handle access points without names", async () => {
			mockS3ControlClient.on(ListAccessPointsCommand).resolves({
				AccessPointList: [{ AccessPointArn: "arn:aws:s3:..." }]
			});

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Access point found without name");
		});

		it("should return ERROR when STS GetCallerIdentity fails", async () => {
			mockSTSClient.on(GetCallerIdentityCommand).rejects(new Error("STS Error"));

			const result = await checkS3AccessPointBlockPublicAccess.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking S3 access points");
		});
	});
});
