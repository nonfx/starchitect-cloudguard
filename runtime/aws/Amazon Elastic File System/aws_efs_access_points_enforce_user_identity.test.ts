// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import { EFSClient, DescribeAccessPointsCommand } from "@aws-sdk/client-efs";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEfsAccessPointUserIdentity from "./aws_efs_access_points_enforce_user_identity";

const mockEfsClient = mockClient(EFSClient);

const mockValidAccessPoint = {
	AccessPointId: "fsap-valid123",
	AccessPointArn: "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-valid123",
	PosixUser: {
		Uid: 1000,
		Gid: 1000
	}
};

const mockInvalidAccessPoint = {
	AccessPointId: "fsap-invalid456",
	AccessPointArn: "arn:aws:elasticfilesystem:us-east-1:123456789012:access-point/fsap-invalid456",
	PosixUser: null
};

describe("checkEfsAccessPointUserIdentity", () => {
	beforeEach(() => {
		mockEfsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when access point has valid POSIX user configuration", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: [mockValidAccessPoint]
			});

			const result = await checkEfsAccessPointUserIdentity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("fsap-valid123");
			expect(result.checks[0].resourceArn).toBe(mockValidAccessPoint.AccessPointArn);
		});

		it("should return NOTAPPLICABLE when no access points exist", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: []
			});

			const result = await checkEfsAccessPointUserIdentity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EFS access points found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when access point has no POSIX user configuration", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: [mockInvalidAccessPoint]
			});

			const result = await checkEfsAccessPointUserIdentity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"EFS access point does not have a valid POSIX user identity configured"
			);
		});

		it("should handle mixed compliance scenarios", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: [mockValidAccessPoint, mockInvalidAccessPoint]
			});

			const result = await checkEfsAccessPointUserIdentity.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});

		it("should handle access points without ARN", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({
				AccessPoints: [{ AccessPointId: "fsap-noarn789" }]
			});

			const result = await checkEfsAccessPointUserIdentity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Access point found without ARN");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).rejects(new Error("API Error"));

			const result = await checkEfsAccessPointUserIdentity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EFS access points: API Error");
		});

		it("should handle undefined AccessPoints in response", async () => {
			mockEfsClient.on(DescribeAccessPointsCommand).resolves({});

			const result = await checkEfsAccessPointUserIdentity.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EFS access points found in the region");
		});
	});
});
