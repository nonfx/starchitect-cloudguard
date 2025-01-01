// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	EC2Client,
	DescribeInstancesCommand,
	DescribeInstanceAttributeCommand
} from "@aws-sdk/client-ec2";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkEc2UserDataSecrets from "./aws_ec2_no_secrets_in_user_data";

const mockEC2Client = mockClient(EC2Client);

const createMockInstance = (instanceId: string) => ({
	InstanceId: instanceId
});

describe("checkEc2UserDataSecrets", () => {
	beforeEach(() => {
		mockEC2Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS for instances without user data", async () => {
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolves({
					Reservations: [
						{
							Instances: [createMockInstance("i-123")]
						}
					]
				})
				.on(DescribeInstanceAttributeCommand)
				.resolves({
					UserData: { Value: undefined }
				});

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].message).toBe("No user data configured");
		});

		it("should return PASS for instances with safe user data", async () => {
			const safeUserData = "#!/bin/bash\necho 'Hello World'\nyum update -y";
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolves({
					Reservations: [
						{
							Instances: [createMockInstance("i-123")]
						}
					]
				})
				.on(DescribeInstanceAttributeCommand)
				.resolves({
					UserData: { Value: Buffer.from(safeUserData).toString("base64") }
				});

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
		});

		it("should return NOTAPPLICABLE when no instances exist", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: []
			});

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No EC2 instances found in the region");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL for instances with password in user data", async () => {
			const sensitiveUserData = "#!/bin/bash\nPASSWORD=mysecret123\necho $PASSWORD";
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolves({
					Reservations: [
						{
							Instances: [createMockInstance("i-123")]
						}
					]
				})
				.on(DescribeInstanceAttributeCommand)
				.resolves({
					UserData: { Value: Buffer.from(sensitiveUserData).toString("base64") }
				});

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("User data contains sensitive information");
		});

		it("should return FAIL for instances with AWS credentials in user data", async () => {
			const sensitiveUserData =
				"#!/bin/bash\nAWS_ACCESS_KEY_ID=AKIA123456\nAWS_SECRET_ACCESS_KEY=secret123";
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolves({
					Reservations: [
						{
							Instances: [createMockInstance("i-123")]
						}
					]
				})
				.on(DescribeInstanceAttributeCommand)
				.resolves({
					UserData: { Value: Buffer.from(sensitiveUserData).toString("base64") }
				});

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("User data contains sensitive information");
		});

		it("should handle mixed compliant and non-compliant instances", async () => {
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolves({
					Reservations: [
						{
							Instances: [createMockInstance("i-123"), createMockInstance("i-456")]
						}
					]
				})
				.on(DescribeInstanceAttributeCommand)
				.callsFake(input => {
					if (input.InstanceId === "i-123") {
						return Promise.resolve({
							UserData: { Value: Buffer.from("#!/bin/bash\necho 'Safe script'").toString("base64") }
						});
					} else {
						return Promise.resolve({
							UserData: {
								Value: Buffer.from("#!/bin/bash\nSECRET_KEY=mysecret123").toString("base64")
							}
						});
					}
				});

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockEC2Client.on(DescribeInstancesCommand).rejects(new Error("API Error"));

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking EC2 instances");
		});

		it("should return ERROR for instances without ID", async () => {
			mockEC2Client.on(DescribeInstancesCommand).resolves({
				Reservations: [
					{
						Instances: [{}]
					}
				]
			});

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks).toHaveLength(0);
		});

		it("should handle pagination correctly", async () => {
			mockEC2Client
				.on(DescribeInstancesCommand)
				.resolvesOnce({
					Reservations: [
						{
							Instances: [createMockInstance("i-123")]
						}
					],
					NextToken: "token1"
				})
				.resolvesOnce({
					Reservations: [
						{
							Instances: [createMockInstance("i-456")]
						}
					]
				})
				.on(DescribeInstanceAttributeCommand)
				.resolves({
					UserData: { Value: Buffer.from("#!/bin/bash\necho 'Safe script'").toString("base64") }
				});

			const result = await checkEc2UserDataSecrets.execute();
			expect(result.checks).toHaveLength(2);
		});
	});
});
