//@ts-nocheck
import { EC2Client, DescribeInstancesCommand } from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEbsDeleteOnTermination from "./check-ebs-delete-on-termination";

const mockEC2Client = mockClient(EC2Client);

const mockCompliantInstance = {
	InstanceId: "i-1234567890abcdef0",
	RootDeviceName: "/dev/xvda",
	BlockDeviceMappings: [
		{
			DeviceName: "/dev/xvda",
			Ebs: {
				VolumeId: "vol-1234567890",
				DeleteOnTermination: true
			}
		},
		{
			DeviceName: "/dev/sdf",
			Ebs: {
				VolumeId: "vol-0987654321",
				DeleteOnTermination: true
			}
		}
	]
};

const mockNonCompliantInstance = {
	InstanceId: "i-0987654321fedcba0",
	RootDeviceName: "/dev/xvda",
	BlockDeviceMappings: [
		{
			DeviceName: "/dev/xvda",
			Ebs: {
				VolumeId: "vol-1234567890",
				DeleteOnTermination: false
			}
		},
		{
			DeviceName: "/dev/sdf",
			Ebs: {
				VolumeId: "vol-0987654321",
				DeleteOnTermination: false
			}
		}
	]
};

describe("checkEbsDeleteOnTermination", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when all volumes are set to delete on termination", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockCompliantInstance]
					}
				]
			});

			const result = await checkEbsDeleteOnTermination.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe(
				`${mockCompliantInstance.InstanceId}:vol-1234567890`
			);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].resourceName).toBe(
				`${mockCompliantInstance.InstanceId}:vol-0987654321`
			);
		});

		it("should return NOTAPPLICABLE when no instances exist", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: []
			});

			const result = await checkEbsDeleteOnTermination.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EC2 instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when volumes are not set to delete on termination", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockNonCompliantInstance]
					}
				]
			});

			const result = await checkEbsDeleteOnTermination.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].resourceName).toBe(
				`${mockNonCompliantInstance.InstanceId}:vol-1234567890`
			);
			expect(result.checks[0].message).toBe("Root volume is not set to delete on termination");
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].resourceName).toBe(
				`${mockNonCompliantInstance.InstanceId}:vol-0987654321`
			);
			expect(result.checks[1].message).toBe("Volume is not set to delete on termination");
		});

		it("should handle mixed compliance scenarios", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [mockCompliantInstance, mockNonCompliantInstance]
					}
				]
			});

			const result = await checkEbsDeleteOnTermination.execute("us-east-1");
			expect(result.checks).toHaveLength(4);
			// First instance's volumes (compliant)
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
			// Second instance's volumes (non-compliant)
			expect(result.checks[2].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[3].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeInstancesCommand).rejects(new Error("API Error"));

			const result = await checkEbsDeleteOnTermination.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EC2 instances");
		});

		it("should handle instances without BlockDeviceMappings", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [
							{
								InstanceId: "i-test",
								RootDeviceName: "/dev/xvda"
							}
						]
					}
				]
			});

			const result = await checkEbsDeleteOnTermination.execute("us-east-1");
			expect(result.checks).toHaveLength(0);
		});
	});
});
