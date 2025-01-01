// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { EFSClient, DescribeAccessPointsCommand } from "@aws-sdk/client-efs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEfsAccessPointsRootDirectory from "./aws_efs_access_points_enforce_root_directory";

const mockEfsClient = mockClient(EFSClient);

const mockCompliantAccessPoint = {
	AccessPointId: "fsap-compliant123",
	AccessPointArn: "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-compliant123",
	RootDirectory: {
		Path: "/data"
	}
};

const mockNonCompliantAccessPoint = {
	AccessPointId: "fsap-noncompliant456",
	AccessPointArn:
		"arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-noncompliant456",
	RootDirectory: {
		Path: "/"
	}
};

describe("checkEfsAccessPointsRootDirectory", () => {
	beforeEach(() => {
		mockEfsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when access point has valid root directory", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: [mockCompliantAccessPoint]
			});

			const result = await checkEfsAccessPointsRootDirectory.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("fsap-compliant123");
			expect(result.checks[0].resourceArn).toBe(mockCompliantAccessPoint.AccessPointArn);
		});

		it("should handle multiple compliant access points", async () => {
			const multipleCompliant = [
				mockCompliantAccessPoint,
				{
					...mockCompliantAccessPoint,
					AccessPointId: "fsap-compliant789",
					AccessPointArn:
						"arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-compliant789",
					RootDirectory: { Path: "/apps" }
				}
			];

			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: multipleCompliant
			});

			const result = await checkEfsAccessPointsRootDirectory.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when access point uses root path", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: [mockNonCompliantAccessPoint]
			});

			const result = await checkEfsAccessPointsRootDirectory.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				'EFS access point does not enforce a root directory or uses root path "/"'
			);
		});

		it("should handle mixed compliant and non-compliant access points", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: [mockCompliantAccessPoint, mockNonCompliantAccessPoint]
			});

			const result = await checkEfsAccessPointsRootDirectory.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Edge Cases and Error Handling", () => {
		it("should return NOTAPPLICABLE when no access points exist", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: []
			});

			const result = await checkEfsAccessPointsRootDirectory.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EFS access points found in the region");
		});

		it("should handle access points without ARN", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: [
					{
						AccessPointId: "fsap-noarn",
						RootDirectory: { Path: "/data" }
					}
				]
			});

			const result = await checkEfsAccessPointsRootDirectory.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Access point found without ARN");
		});

		it("should handle API errors", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).rejects(new Error("API Error"));

			const result = await checkEfsAccessPointsRootDirectory.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EFS access points: API Error");
		});

		it("should handle pagination", async () => {
			mockEfsClient
				.on(DescribeAccessPointsCommand)
				.resolvesOnce({
					AccessPoints: [mockCompliantAccessPoint],
					NextToken: "token1"
				})
				.resolvesOnce({
					AccessPoints: [mockNonCompliantAccessPoint]
				});

			const result = await checkEfsAccessPointsRootDirectory.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
