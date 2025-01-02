// @ts-nocheck
import {
	ConfigServiceClient,
	DescribeConfigurationRecordersCommand,
	DescribeConfigurationRecorderStatusCommand
} from "@aws-sdk/client-config-service";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types.js";
import checkAwsConfigLambda from "./check-aws-config-lambda";

const mockConfigServiceClient = mockClient(ConfigServiceClient);

const mockCompliantRecorder = {
	name: "compliant-recorder",
	recordingGroup: {
		allSupported: true,
		includeGlobalResourceTypes: true,
		recordingStrategy: {
			useOnly: "ALL_SUPPORTED_RESOURCE_TYPES"
		},
		resourceTypes: ["AWS::Lambda::Function"]
	}
};

const mockNonCompliantRecorder = {
	name: "non-compliant-recorder",
	recordingGroup: {
		allSupported: false,
		includeGlobalResourceTypes: false,
		recordingStrategy: {
			useOnly: "INCLUSION_BY_RESOURCE_TYPES"
		},
		resourceTypes: []
	}
};

describe("checkAwsConfigLambda", () => {
	beforeEach(() => {
		mockConfigServiceClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Config recorder is properly configured for Lambda", async () => {
			mockConfigServiceClient
				.on(DescribeConfigurationRecordersCommand)
				.resolves({
					ConfigurationRecorders: [mockCompliantRecorder]
				})
				.on(DescribeConfigurationRecorderStatusCommand)
				.resolves({
					ConfigurationRecordersStatus: [
						{
							name: "compliant-recorder",
							recording: true
						}
					]
				});

			const result = await checkAwsConfigLambda.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("compliant-recorder");
		});

		it("should handle multiple compliant recorders", async () => {
			mockConfigServiceClient
				.on(DescribeConfigurationRecordersCommand)
				.resolves({
					ConfigurationRecorders: [mockCompliantRecorder, mockCompliantRecorder]
				})
				.on(DescribeConfigurationRecorderStatusCommand)
				.resolves({
					ConfigurationRecordersStatus: [
						{ name: "compliant-recorder", recording: true },
						{ name: "compliant-recorder", recording: true }
					]
				});

			const result = await checkAwsConfigLambda.execute("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no Config recorders exist", async () => {
			mockConfigServiceClient
				.on(DescribeConfigurationRecordersCommand)
				.resolves({ ConfigurationRecorders: [] });

			const result = await checkAwsConfigLambda.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No AWS Config configuration recorders found");
		});

		it("should return FAIL when recorder is not enabled", async () => {
			mockConfigServiceClient
				.on(DescribeConfigurationRecordersCommand)
				.resolves({
					ConfigurationRecorders: [mockCompliantRecorder]
				})
				.on(DescribeConfigurationRecorderStatusCommand)
				.resolves({
					ConfigurationRecordersStatus: [
						{
							name: "compliant-recorder",
							recording: false
						}
					]
				});

			const result = await checkAwsConfigLambda.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Config recorder is not enabled");
		});

		it("should return FAIL when Lambda resources are not included", async () => {
			mockConfigServiceClient
				.on(DescribeConfigurationRecordersCommand)
				.resolves({
					ConfigurationRecorders: [mockNonCompliantRecorder]
				})
				.on(DescribeConfigurationRecorderStatusCommand)
				.resolves({
					ConfigurationRecordersStatus: [
						{
							name: "non-compliant-recorder",
							recording: true
						}
					]
				});

			const result = await checkAwsConfigLambda.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("Lambda resources are not included");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockConfigServiceClient
				.on(DescribeConfigurationRecordersCommand)
				.rejects(new Error("API Error"));

			const result = await checkAwsConfigLambda.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking AWS Config");
		});

		it("should handle missing recorder status", async () => {
			mockConfigServiceClient
				.on(DescribeConfigurationRecordersCommand)
				.resolves({
					ConfigurationRecorders: [mockCompliantRecorder]
				})
				.on(DescribeConfigurationRecorderStatusCommand)
				.resolves({
					ConfigurationRecordersStatus: []
				});

			const result = await checkAwsConfigLambda.execute("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
		});
	});
});
