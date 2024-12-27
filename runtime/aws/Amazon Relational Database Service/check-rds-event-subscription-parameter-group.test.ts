//@ts-nocheck
import {
	RDSClient,
	DescribeEventSubscriptionsCommand,
	DescribeDBParameterGroupsCommand,
	type EventSubscription,
	type DBParameterGroup
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "../../types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsEventSubscriptionParameterGroup from "./check-rds-event-subscription-parameter-group";

const mockRDSClient = mockClient(RDSClient);

const mockValidSubscription: EventSubscription = {
	CustSubscriptionId: "valid-subscription",
	EventSubscriptionArn: "arn:aws:rds:us-east-1:123456789012:es:valid-subscription",
	SourceType: "db-parameter-group",
	EventCategoriesList: ["configuration change"],
	SnsTopicArn: "arn:aws:sns:us-east-1:123456789012:rds-events",
	Enabled: true
};

const mockParameterGroup: DBParameterGroup = {
	DBParameterGroupName: "test-param-group",
	DBParameterGroupArn: "arn:aws:rds:us-east-1:123456789012:pg:test-param-group",
	DBParameterGroupFamily: "mysql8.0",
	Description: "Test parameter group"
};

describe("checkRdsEventSubscriptionParameterGroup", () => {
	beforeEach(() => {
		mockRDSClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS when parameter group is monitored by subscription", async () => {
			mockRDSClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [mockValidSubscription]
				})
				.on(DescribeDBParameterGroupsCommand)
				.resolves({
					DBParameterGroups: [mockParameterGroup]
				});

			const result = await checkRdsEventSubscriptionParameterGroup.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-param-group");
		});

		test("should handle subscription with no source IDs (applies to all)", async () => {
			const globalSubscription: EventSubscription = {
				...mockValidSubscription,
				SourceIdsList: []
			};

			mockRDSClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [globalSubscription]
				})
				.on(DescribeDBParameterGroupsCommand)
				.resolves({
					DBParameterGroups: [mockParameterGroup]
				});

			const result = await checkRdsEventSubscriptionParameterGroup.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when no event subscriptions exist", async () => {
			mockRDSClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: []
				})
				.on(DescribeDBParameterGroupsCommand)
				.resolves({
					DBParameterGroups: [mockParameterGroup]
				});

			const result = await checkRdsEventSubscriptionParameterGroup.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("No RDS event subscriptions found");
		});

		test("should return NOTAPPLICABLE when no parameter groups exist", async () => {
			mockRDSClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [mockValidSubscription]
				})
				.on(DescribeDBParameterGroupsCommand)
				.resolves({
					DBParameterGroups: []
				});

			const result = await checkRdsEventSubscriptionParameterGroup.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS parameter groups found");
		});

		test("should return FAIL when parameter group is not monitored", async () => {
			const subscriptionWithDifferentTarget: EventSubscription = {
				...mockValidSubscription,
				SourceIdsList: ["different-param-group"]
			};

			mockRDSClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [subscriptionWithDifferentTarget]
				})
				.on(DescribeDBParameterGroupsCommand)
				.resolves({
					DBParameterGroups: [mockParameterGroup]
				});

			const result = await checkRdsEventSubscriptionParameterGroup.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain(
				"Parameter group changes are not monitored by any event subscription"
			);
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when event subscriptions API call fails", async () => {
			mockRDSClient
				.on(DescribeEventSubscriptionsCommand)
				.rejects(new Error("API Error"))
				.on(DescribeDBParameterGroupsCommand)
				.resolves({
					DBParameterGroups: [mockParameterGroup]
				});

			const result = await checkRdsEventSubscriptionParameterGroup.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking event subscriptions");
		});

		test("should return ERROR when parameter groups API call fails", async () => {
			mockRDSClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [mockValidSubscription]
				})
				.on(DescribeDBParameterGroupsCommand)
				.rejects(new Error("API Error"));

			const result = await checkRdsEventSubscriptionParameterGroup.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking event subscriptions");
		});

		test("should handle parameter groups without names", async () => {
			const incompleteParamGroup: DBParameterGroup = {
				DBParameterGroupFamily: "mysql8.0",
				Description: "Test parameter group"
			};

			mockRDSClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [mockValidSubscription]
				})
				.on(DescribeDBParameterGroupsCommand)
				.resolves({
					DBParameterGroups: [incompleteParamGroup]
				});

			const result = await checkRdsEventSubscriptionParameterGroup.execute();
			expect(result.checks).toHaveLength(0); // Should skip parameter groups without names
		});
	});
});
