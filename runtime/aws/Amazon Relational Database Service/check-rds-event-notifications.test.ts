import { RDSClient, DescribeEventSubscriptionsCommand } from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import checkRdsEventNotifications from "./check-rds-event-notifications";

const mockRdsClient = mockClient(RDSClient);

const mockCompliantSubscription = {
	CustSubscriptionId: "test-subscription-1",
	EventSubscriptionArn: "arn:aws:rds:us-east-1:123456789012:es:test-subscription-1",
	SourceType: "db-instance",
	Enabled: true,
	EventCategoriesList: ["maintenance", "configuration change", "failure"]
};

const mockNonCompliantSubscription = {
	CustSubscriptionId: "test-subscription-2",
	EventSubscriptionArn: "arn:aws:rds:us-east-1:123456789012:es:test-subscription-2",
	SourceType: "db-instance",
	Enabled: true,
	EventCategoriesList: ["maintenance", "failure"] // missing configuration change
};

describe("checkRdsEventNotifications", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		it("should return PASS when subscription has all required categories", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockCompliantSubscription]
			});

			const result = await checkRdsEventNotifications("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0].resourceName).toBe("test-subscription-1");
			expect(result.checks[0].resourceArn).toBe(mockCompliantSubscription.EventSubscriptionArn);
		});

		it("should handle multiple compliant subscriptions", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockCompliantSubscription, mockCompliantSubscription]
			});

			const result = await checkRdsEventNotifications("us-east-1");
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		it("should return FAIL when no subscriptions exist", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: []
			});

			const result = await checkRdsEventNotifications("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toBe("No RDS event subscriptions found");
		});

		it("should return FAIL when missing required categories", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockNonCompliantSubscription]
			});

			const result = await checkRdsEventNotifications("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("missing required event categories");
		});

		it("should return FAIL when subscription is disabled", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [
					{
						...mockCompliantSubscription,
						Enabled: false
					}
				]
			});

			const result = await checkRdsEventNotifications("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("subscription not enabled");
		});

		it("should return FAIL when source type is incorrect", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [
					{
						...mockCompliantSubscription,
						SourceType: "db-cluster"
					}
				]
			});

			const result = await checkRdsEventNotifications("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0].message).toContain("incorrect source type");
		});
	});

	describe("Error Handling", () => {
		it("should return ERROR when API call fails", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).rejects(new Error("API Error"));

			const result = await checkRdsEventNotifications("us-east-1");
			expect(result.checks[0].status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0].message).toContain("Error checking RDS event subscriptions");
		});

		it("should handle subscriptions without CustSubscriptionId", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [
					{
						...mockCompliantSubscription,
						CustSubscriptionId: undefined
					}
				]
			});

			const result = await checkRdsEventNotifications("us-east-1");
			expect(result.checks).toHaveLength(0);
		});
	});
});
