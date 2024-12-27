// eslint-disable-next-line @typescript-eslint/ban-ts-comment
//@ts-nocheck
import {
	Macie2Client,
	GetAutomatedDiscoveryConfigurationCommand,
	DescribeBucketsCommand
} from "@aws-sdk/client-macie2";
import { S3Client, ListBucketsCommand } from "@aws-sdk/client-s3";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkS3DataDiscoveryCompliance from "./check-s3-data-discovery-compliance";

const mockMacieClient = mockClient(Macie2Client);
const mockS3Client = mockClient(S3Client);

const MOCK_BUCKETS = [
	{ Name: "test-bucket-1", CreationDate: new Date() },
	{ Name: "test-bucket-2", CreationDate: new Date() }
];

describe("checkS3DataDiscoveryCompliance", () => {
	beforeEach(() => {
		mockMacieClient.reset();
		mockS3Client.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when Macie is enabled with proper configuration", async () => {
			mockMacieClient
				.on(GetAutomatedDiscoveryConfigurationCommand)
				.resolves({
					status: "ENABLED"
				})
				.on(DescribeBucketsCommand)
				.resolves({
					buckets: [{ bucketName: "test-bucket-1" }, { bucketName: "test-bucket-2" }]
				});

			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: MOCK_BUCKETS
			});

			const result = await checkS3DataDiscoveryCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[2].status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when Macie is disabled", async () => {
			mockMacieClient.on(GetAutomatedDiscoveryConfigurationCommand).resolves({
				status: "DISABLED"
			});

			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: MOCK_BUCKETS
			});

			const result = await checkS3DataDiscoveryCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("Automated sensitive data discovery is not enabled");
		});

		it("should return FAIL when buckets are not monitored", async () => {
			mockMacieClient
				.on(GetAutomatedDiscoveryConfigurationCommand)
				.resolves({
					status: "ENABLED"
				})
				.on(DescribeBucketsCommand)
				.resolves({
					buckets: [] // No monitored buckets
				});

			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: MOCK_BUCKETS
			});

			const result = await checkS3DataDiscoveryCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe(
				"Bucket is not configured for automated sensitive data discovery"
			);
		});

		it("should return NOTAPPLICABLE when no buckets exist", async () => {
			mockMacieClient.on(GetAutomatedDiscoveryConfigurationCommand).resolves({
				status: "ENABLED"
			});

			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: []
			});

			const result = await checkS3DataDiscoveryCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0].message).toBe("No S3 buckets found in the account");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when Macie API call fails", async () => {
			mockMacieClient.on(GetAutomatedDiscoveryConfigurationCommand).rejects(new Error("API Error"));

			mockS3Client.on(ListBucketsCommand).resolves({
				Buckets: MOCK_BUCKETS
			});

			const result = await checkS3DataDiscoveryCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking S3 data discovery: API Error");
		});

		it("should return ERROR when S3 API call fails", async () => {
			mockMacieClient.on(GetAutomatedDiscoveryConfigurationCommand).resolves({
				status: "ENABLED"
			});

			mockS3Client.on(ListBucketsCommand).rejects(new Error("S3 API Error"));

			const result = await checkS3DataDiscoveryCompliance.execute();
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toBe("Error checking S3 data discovery: S3 API Error");
		});
	});
});
