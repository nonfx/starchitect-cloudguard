// @ts-nocheck
import {
	AppRunnerClient,
	ListServicesCommand,
	DescribeServiceCommand
} from "@aws-sdk/client-apprunner";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAppRunnerVpcEndpoint from "./check-app-runner-vpc-endpoint";

const mockAppRunnerClient = mockClient(AppRunnerClient);

const mockService = {
	ServiceArn: "arn:aws:apprunner:us-east-1:123456789012:service/test-service",
	ServiceId: "test-service-id",
	ServiceName: "test-service"
};

describe("checkAppRunnerVpcEndpoint", () => {
	beforeEach(() => {
		mockAppRunnerClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when service uses VPC connector", async () => {
			mockAppRunnerClient.on(ListServicesCommand).resolves({
				ServiceSummaryList: [mockService]
			});
			mockAppRunnerClient.on(DescribeServiceCommand).resolves({
				Service: {
					NetworkConfiguration: {
						EgressConfiguration: {
							EgressType: "VPC"
						}
					}
				}
			});

			const result = await checkAppRunnerVpcEndpoint.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-service");
		});

		it("should return NOTAPPLICABLE when no App Runner services exist", async () => {
			mockAppRunnerClient.on(ListServicesCommand).resolves({
				ServiceSummaryList: []
			});

			const result = await checkAppRunnerVpcEndpoint.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No App Runner services found");
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when service is not using VPC connector", async () => {
			mockAppRunnerClient.on(ListServicesCommand).resolves({
				ServiceSummaryList: [mockService]
			});
			mockAppRunnerClient.on(DescribeServiceCommand).resolves({
				Service: {
					NetworkConfiguration: {
						EgressConfiguration: {
							EgressType: "DEFAULT" // Not using VPC connector
						}
					}
				}
			});

			const result = await checkAppRunnerVpcEndpoint.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Service is not using a VPC connector");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when ListServices fails", async () => {
			mockAppRunnerClient.on(ListServicesCommand).rejects(new Error("API Error"));

			const result = await checkAppRunnerVpcEndpoint.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking App Runner services");
		});

		it("should return ERROR when DescribeService fails", async () => {
			mockAppRunnerClient.on(ListServicesCommand).resolves({
				ServiceSummaryList: [mockService]
			});
			mockAppRunnerClient.on(DescribeServiceCommand).rejects(new Error("Service Error"));

			const result = await checkAppRunnerVpcEndpoint.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking App Runner services");
		});
	});
});
