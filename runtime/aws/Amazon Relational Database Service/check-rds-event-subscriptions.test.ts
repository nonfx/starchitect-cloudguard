//@ts-nocheck
import {
	RDSClient,
	DescribeEventSubscriptionsCommand,
	DescribeDBInstancesCommand,
	DescribeDBClustersCommand,
	type EventSubscription,
	type DBInstance,
	type DBCluster
} from "@aws-sdk/client-rds";
import { mockClient } from "aws-sdk-client-mock";
import { ComplianceStatus } from "~runtime/types";
import { test, describe, expect, beforeEach } from "bun:test";
import checkRdsEventSubscriptions from "./check-rds-event-subscriptions";

const mockRdsClient = mockClient(RDSClient);

const mockClusterSubscription: EventSubscription = {
	CustSubscriptionId: "test-cluster-sub",
	EventSubscriptionArn: "arn:aws:rds:us-east-1:123456789012:es:test-cluster-sub",
	Enabled: true,
	SourceType: "db-cluster",
	SnsTopicArn: "arn:aws:sns:us-east-1:123456789012:test-topic",
	EventCategoriesList: ["maintenance", "failure", "notification"]
};

const mockInstanceSubscription: EventSubscription = {
	CustSubscriptionId: "test-instance-sub",
	EventSubscriptionArn: "arn:aws:rds:us-east-1:123456789012:es:test-instance-sub",
	Enabled: true,
	SourceType: "db-instance",
	SnsTopicArn: "arn:aws:sns:us-east-1:123456789012:test-topic",
	EventCategoriesList: ["maintenance", "failure", "notification"]
};

const mockInstance: DBInstance = {
	DBInstanceIdentifier: "test-instance",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-instance"
};

const mockClusterInstance: DBInstance = {
	DBInstanceIdentifier: "test-cluster-instance",
	DBInstanceArn: "arn:aws:rds:us-east-1:123456789012:db:test-cluster-instance",
	DBClusterIdentifier: "test-cluster"
};

const mockCluster: DBCluster = {
	DBClusterIdentifier: "test-cluster",
	DBClusterArn: "arn:aws:rds:us-east-1:123456789012:cluster:test-cluster"
};

describe("checkRdsEventSubscriptions", () => {
	beforeEach(() => {
		mockRdsClient.reset();
	});

	describe("Compliant Resources", () => {
		test("should return PASS for instance with valid subscription", async () => {
			mockRdsClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [mockInstanceSubscription]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockInstance]
				})
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				});

			const result = await checkRdsEventSubscriptions.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-instance");
		});

		test("should return PASS for cluster instance with cluster subscription", async () => {
			mockRdsClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [mockClusterSubscription]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockClusterInstance]
				})
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: [mockCluster]
				});

			const result = await checkRdsEventSubscriptions.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
			expect(result.checks[0]?.resourceName).toBe("test-cluster-instance");
		});

		test("should handle subscription with no event categories (monitors all)", async () => {
			const allEventsSubscription: EventSubscription = {
				...mockInstanceSubscription,
				EventCategoriesList: []
			};

			mockRdsClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [allEventsSubscription]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockInstance]
				})
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				});

			const result = await checkRdsEventSubscriptions.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.PASS);
		});
	});

	describe("Non-Compliant Resources", () => {
		test("should return FAIL when no subscriptions exist", async () => {
			mockRdsClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: []
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockInstance]
				})
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				});

			const result = await checkRdsEventSubscriptions.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toBe("No RDS event subscriptions found");
		});

		test("should return NOTAPPLICABLE when no instances exist", async () => {
			mockRdsClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [mockInstanceSubscription]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: []
				})
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				});

			const result = await checkRdsEventSubscriptions.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.NOTAPPLICABLE);
			expect(result.checks[0]?.message).toBe("No RDS instances found");
		});

		test("should return FAIL for missing required event categories", async () => {
			const incompleteSubscription: EventSubscription = {
				...mockInstanceSubscription,
				EventCategoriesList: ["notification"]
			};

			mockRdsClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [incompleteSubscription]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [mockInstance]
				})
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				});

			const result = await checkRdsEventSubscriptions.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.FAIL);
			expect(result.checks[0]?.message).toContain("Missing event categories");
		});
	});

	describe("Error Handling", () => {
		test("should return ERROR when API call fails", async () => {
			mockRdsClient.on(DescribeEventSubscriptionsCommand).rejects(new Error("API Error"));

			const result = await checkRdsEventSubscriptions.execute();
			expect(result.checks[0]?.status).toBe(ComplianceStatus.ERROR);
			expect(result.checks[0]?.message).toContain("Error checking RDS event subscriptions");
		});

		test("should handle instances without identifiers", async () => {
			const incompleteInstance: DBInstance = {};

			mockRdsClient
				.on(DescribeEventSubscriptionsCommand)
				.resolves({
					EventSubscriptionsList: [mockInstanceSubscription]
				})
				.on(DescribeDBInstancesCommand)
				.resolves({
					DBInstances: [incompleteInstance]
				})
				.on(DescribeDBClustersCommand)
				.resolves({
					DBClusters: []
				});

			const result = await checkRdsEventSubscriptions.execute();
			expect(result.checks).toHaveLength(0);
		});
	});
});
