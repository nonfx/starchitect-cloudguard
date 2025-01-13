// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	ConfigServiceClient,
	DescribeConfigurationRecordersCommand,
	DescribeConfigurationRecorderStatusCommand,
	GetDiscoveredResourceCountsCommand
} from "@aws-sdk/client-config-service";
import { mockClient } from "aws-sdk-client-mock";
import checkConfigEnabledAllRegions from "./check-config-enabled-all-regions";
import { ComplianceStatus } from "../../types.js";

const mockConfigClient = mockClient(ConfigServiceClient);

describe("checkConfigEnabledAllRegions", () => {
	beforeEach(() => {
		mockConfigClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Config is properly configured and active", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: [
					{
						name: "test-recorder",
						recordingGroup: {
							allSupported: true,
							includeGlobalResourceTypes: true
						}
					}
				]
			});

			mockConfigClient.on(DescribeConfigurationRecorderStatusCommand).resolves({
				ConfigurationRecordersStatus: [
					{
						name: "test-recorder",
						recording: true
					}
				]
			});

			mockConfigClient.on(GetDiscoveredResourceCountsCommand).resolves({
				totalDiscoveredResources: 100
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-recorder");
			expect(result.checks[0].message).toBe(
				"Configuration recorder is properly configured and active"
			);
		});

		it("should handle multiple compliant recorders", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: [
					{
						name: "recorder-1",
						recordingGroup: {
							allSupported: true,
							includeGlobalResourceTypes: true
						}
					},
					{
						name: "recorder-2",
						recordingGroup: {
							allSupported: true,
							includeGlobalResourceTypes: true
						}
					}
				]
			});

			mockConfigClient.on(DescribeConfigurationRecorderStatusCommand).resolves({
				ConfigurationRecordersStatus: [
					{
						name: "recorder-1",
						recording: true
					},
					{
						name: "recorder-2",
						recording: true
					}
				]
			});

			mockConfigClient.on(GetDiscoveredResourceCountsCommand).resolves({
				totalDiscoveredResources: 100
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no configuration recorders exist", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: []
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"No configuration recorders found. AWS Config is not enabled."
			);
		});

		it("should return FAIL when recorder status is not found", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: [
					{
						name: "test-recorder"
					}
				]
			});

			mockConfigClient.on(DescribeConfigurationRecorderStatusCommand).resolves({
				ConfigurationRecordersStatus: []
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Configuration recorder status not found.");
		});

		it("should return FAIL when recorder is not recording all resources", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: [
					{
						name: "test-recorder",
						recordingGroup: {
							allSupported: false,
							includeGlobalResourceTypes: true
						}
					}
				]
			});

			mockConfigClient.on(DescribeConfigurationRecorderStatusCommand).resolves({
				ConfigurationRecordersStatus: [
					{
						name: "test-recorder",
						recording: true
					}
				]
			});

			mockConfigClient.on(GetDiscoveredResourceCountsCommand).resolves({
				totalDiscoveredResources: 100
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not recording all resource types");
		});

		it("should return FAIL when recorder is not recording global resources", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: [
					{
						name: "test-recorder",
						recordingGroup: {
							allSupported: true,
							includeGlobalResourceTypes: false
						}
					}
				]
			});

			mockConfigClient.on(DescribeConfigurationRecorderStatusCommand).resolves({
				ConfigurationRecordersStatus: [
					{
						name: "test-recorder",
						recording: true
					}
				]
			});

			mockConfigClient.on(GetDiscoveredResourceCountsCommand).resolves({
				totalDiscoveredResources: 100
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("not recording global resources");
		});

		it("should return FAIL when recorder is not active", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: [
					{
						name: "test-recorder",
						recordingGroup: {
							allSupported: true,
							includeGlobalResourceTypes: true
						}
					}
				]
			});

			mockConfigClient.on(DescribeConfigurationRecorderStatusCommand).resolves({
				ConfigurationRecordersStatus: [
					{
						name: "test-recorder",
						recording: false
					}
				]
			});

			mockConfigClient.on(GetDiscoveredResourceCountsCommand).resolves({
				totalDiscoveredResources: 100
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("recorder is not active");
		});

		it("should return FAIL when no resources are being recorded", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: [
					{
						name: "test-recorder",
						recordingGroup: {
							allSupported: true,
							includeGlobalResourceTypes: true
						}
					}
				]
			});

			mockConfigClient.on(DescribeConfigurationRecorderStatusCommand).resolves({
				ConfigurationRecordersStatus: [
					{
						name: "test-recorder",
						recording: true
					}
				]
			});

			mockConfigClient.on(GetDiscoveredResourceCountsCommand).resolves({
				totalDiscoveredResources: 0
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[1].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[1].message).toBe("No resources are being recorded by AWS Config");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).rejects(new Error("API Error"));

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking AWS Config: API Error");
		});

		it("should handle undefined recorder name", async () => {
			mockConfigClient.on(DescribeConfigurationRecordersCommand).resolves({
				ConfigurationRecorders: [
					{
						recordingGroup: {
							allSupported: true,
							includeGlobalResourceTypes: true
						}
					}
				]
			});

			mockConfigClient.on(DescribeConfigurationRecorderStatusCommand).resolves({
				ConfigurationRecordersStatus: [
					{
						name: "Unknown Recorder",
						recording: true
					}
				]
			});

			mockConfigClient.on(GetDiscoveredResourceCountsCommand).resolves({
				totalDiscoveredResources: 100
			});

			const result = await checkConfigEnabledAllRegions.execute();
			expect(result.checks[0].resourceName).toBe("Unknown Recorder");
		});
	});
});
