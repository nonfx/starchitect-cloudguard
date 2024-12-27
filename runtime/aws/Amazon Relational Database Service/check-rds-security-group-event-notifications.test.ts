//@ts-nocheck
import {
	RDSClient,
	DescribeEventSubscriptionsCommand,
	type EventSubscription
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsSecurityGroupEventNotifications from "./check-rds-security-group-event-notifications";

const mockRDSClient = mockClient(RDSClient);

const mockEnabledSubscription: EventSubscription = {
	CustSubscriptionId: "test-subscription-1",
	EventSubscriptionArn: "arn:aws:rds:us-east-1:123456789012:es:test-subscription-1",
	SourceType: "db-security-group",
	Enabled: true,
	SnsTopicArn: "arn:aws:sns:us-east-1:123456789012:test-topic"
};

const mockDisabledSubscription: EventSubscription = {
	CustSubscriptionId: "test-subscription-2",
	EventSubscriptionArn: "arn:aws:rds:us-east-1:123456789012:es:test-subscription-2",
	SourceType: "db-security-group",
	Enabled: false,
	SnsTopicArn: "arn:aws:sns:us-east-1:123456789012:test-topic"
};

describe("checkRdsSecurityGroupEventNotifications", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when security group event subscription is enabled", async () => {
			mockRDSClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockEnabledSubscription]
			});

			const result = await checkRdsSecurityGroupEventNotifications.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-subscription-1");
			expect(result.checks[0]?.resourceArn).toBe(mockEnabledSubscription.EventSubscriptionArn);
		});

		test("should handle multiple enabled subscriptions", async () => {
			const secondSubscription: EventSubscription = {
				...mockEnabledSubscription,
				CustSubscriptionId: "test-subscription-3",
				EventSubscriptionArn: "arn:aws:rds:us-east-1:123456789012:es:test-subscription-3"
			};

			mockRDSClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockEnabledSubscription, secondSubscription]
			});

			const result = await checkRdsSecurityGroupEventNotifications.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks.every(check => check.status === ComplianceStatus.PASS)).toBe(true);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when no event subscriptions exist", async () => {
			mockRDSClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: []
			});

			const result = await checkRdsSecurityGroupEventNotifications.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("No RDS event subscriptions found");
		});

		test("should return FAIL when security group event subscription is disabled", async () => {
			mockRDSClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockDisabledSubscription]
			});

			const result = await checkRdsSecurityGroupEventNotifications.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"Security group event subscription issues: subscription is disabled"
			);
		});

		test("should return FAIL when no security group specific subscriptions exist", async () => {
			const nonSecurityGroupSub: EventSubscription = {
				...mockEnabledSubscription,
				SourceType: "db-instance"
			};

			mockRDSClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [nonSecurityGroupSub]
			});

			const result = await checkRdsSecurityGroupEventNotifications.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe(
				"No event subscriptions configured for database security group events"
			);
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRDSClient.on(DescribeEventSubscriptionsCommand).rejects(new Error("API Error"));

			const result = await checkRdsSecurityGroupEventNotifications.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking event subscriptions");
		});

		test("should return ERROR for malformed subscription data", async () => {
			const incompleteSubscription: EventSubscription = {
				SourceType: "db-security-group",
				Enabled: true
			};

			mockRDSClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [incompleteSubscription]
			});

			const result = await checkRdsSecurityGroupEventNotifications.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toBe("Subscription found without ID or ARN");
		});
	});

	describe("Mixed Scenarios", () => {
		test("should handle mix of enabled and disabled subscriptions", async () => {
			mockRDSClient.on(DescribeEventSubscriptionsCommand).resolves({
				EventSubscriptionsList: [mockEnabledSubscription, mockDisabledSubscription]
			});

			const result = await checkRdsSecurityGroupEventNotifications.execute();
			expect(result.checks).toHaveLength(2);
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[1]?.status).toBe(ComplianceStatus.FAIL);
		});
	});
});
